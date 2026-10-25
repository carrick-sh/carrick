//! Host-only physical service for production native signal path witnesses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use carrick_guest_arch::{ContextGeneration, FrameGpa};
use carrick_sched_core::ParkedContextWords;

std::thread_local! {
    static SIGNAL_COPIES: std::cell::RefCell<Vec<(UserVa, Vec<u8>)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

pub fn take_signal_copies() -> Vec<(UserVa, Vec<u8>)> {
    SIGNAL_COPIES.with(|copies| core::mem::take(&mut *copies.borrow_mut()))
}

pub struct Physical<'a, C: ProcessContext = ParkedContextWords> {
    pub zone: &'a ZoneTables<C>,
    pub page: &'a ThreadLifecyclePage,
    pub controls: &'a [ThreadControlSlot],
    pub copies: Vec<LinuxWaitStatus>,
    pub tid_words: BTreeMap<(u64, u64), u32>,
    pub tid_wakes: usize,
    pub tid_writes: Vec<(u64, u64, u32)>,
    pub child_copy_error: Option<NativeProcessError>,
    pub refuse_copy: bool,
    pub on_signal_clock: Option<Box<dyn FnMut() + 'a>>,
}
impl<'a, C: ProcessContext> NativeProcessService<'a, C> for Physical<'a, C> {
    type Mm = AddressContext<RootGpa>;
    type PreparedMm = AddressContext<RootGpa>;
    type Born = AddressContext<RootGpa>;
    fn adopt_exec_successor(
        &self,
        identity: carrick_core_abi::service::ServiceIdentity,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        manifest: &carrick_core_abi::service::ExecSuccessorManifest,
    ) -> Result<NativeExecSuccessor<Self::Mm, C>, NativeProcessError> {
        let sealed = manifest
            .open(identity, receipt)
            .ok_or(NativeProcessError::Stale)?;
        let address = AddressContext {
            root: sealed.root,
            mm: MmGeneration::new(NonZeroU64::new(sealed.successor_mm.raw()).unwrap()),
            generation: ContextGeneration::new(sealed.root_generation),
        };
        let ttbr = (u64::from(sealed.asid.raw()) << 48) | sealed.root.address().raw();
        self.zone
            .spaces
            .publish_closed(sealed.successor_mm.raw(), ttbr, ttbr)
            .ok_or(NativeProcessError::Stale)?;
        let words = <C as zerocopy::FromZeros>::new_zeroed().fork_child(address);
        Ok(NativeExecSuccessor {
            mm: address,
            address,
            words: Box::new(words),
        })
    }
    fn finish_exec_successor(
        &self,
        predecessor: AddressContext<RootGpa>,
        successor: AddressContext<RootGpa>,
    ) -> Result<(), NativeProcessError> {
        let old = self
            .zone
            .spaces
            .find(predecessor.mm.raw().get())
            .ok_or(NativeProcessError::Stale)?;
        let new = self
            .zone
            .spaces
            .find(successor.mm.raw().get())
            .ok_or(NativeProcessError::Stale)?;
        let slot = (0..carrick_sched_core::ZONE_SLOTS)
            .filter_map(SlotId::from_index)
            .find(|slot| self.zone.installed_space(*slot) == predecessor.mm.raw().get())
            .ok_or(NativeProcessError::Stale)?;
        self.zone.spaces.close(old);
        self.zone.release_space(slot);
        self.zone.spaces.free(old);
        self.zone.spaces.open(new);
        self.zone
            .install_space(slot, successor.mm.raw().get())
            .ok_or(NativeProcessError::Stale)?;
        Ok(())
    }
    fn exec_fd_map(&self) -> &[carrick_el1_abi::FdMapSlot] {
        static MAP: std::sync::OnceLock<&'static [carrick_el1_abi::FdMapSlot]> =
            std::sync::OnceLock::new();
        MAP.get_or_init(|| {
            Box::leak(
                (0..carrick_el1_abi::FD_MAP_CAPACITY)
                    .map(|_| carrick_el1_abi::FdMapSlot::default())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        })
    }
    fn exec_open_table(&self) -> &[carrick_el1_abi::DelegatedOpenFile] {
        static TABLE: std::sync::OnceLock<&'static [carrick_el1_abi::DelegatedOpenFile]> =
            std::sync::OnceLock::new();
        TABLE.get_or_init(|| {
            Box::leak(
                (0..16)
                    .map(|_| carrick_el1_abi::DelegatedOpenFile::new())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        })
    }
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
        _: &C,
        child: MmGeneration,
    ) -> Result<Self::PreparedMm, NativeProcessError> {
        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap(),
            mm: child,
            generation: ContextGeneration::new(NonZeroU64::MIN),
        };
        self.zone
            .spaces
            .publish_closed(child.raw().get(), address.root.address().raw(), 0)
            .ok_or(NativeProcessError::Exhausted)?;
        for ((mm, va), value) in self.tid_words.clone() {
            if mm == parent.mm.raw().get() {
                self.tid_words.insert((child.raw().get(), va), value);
            }
        }
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
            page: self.page,
            controls: self.controls,
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
        p: Self::PreparedMm,
    ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
        self.zone
            .spaces
            .free(self.zone.spaces.find(p.mm.raw().get()).unwrap());
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
        status: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError> {
        if self.refuse_copy {
            return Err(NativeProcessError::Fault);
        };
        self.copies.push(status);
        Ok(())
    }
    fn copy_signal_bytes(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        if let Some(error) = self.child_copy_error {
            return Err(error);
        }
        if bytes.len() == core::mem::size_of::<u32>() {
            let Some(word) = self.tid_words.get_mut(&(mm.mm.raw().get(), address.raw())) else {
                return Err(NativeProcessError::Fault);
            };
            let bytes: [u8; 4] = bytes.try_into().map_err(|_| NativeProcessError::Fault)?;
            *word = u32::from_ne_bytes(bytes);
            self.tid_writes
                .push((mm.mm.raw().get(), address.raw(), *word));
        } else {
            SIGNAL_COPIES.with(|copies| copies.borrow_mut().push((address, bytes.to_vec())));
        }
        Ok(())
    }
    fn signal_deadline(
        &mut self,
        nanos: u64,
    ) -> Result<carrick_guest_arch::Deadline, NativeProcessError> {
        Ok(carrick_guest_arch::Deadline(
            carrick_guest_arch::CounterTick::new(1000 + nanos),
        ))
    }
    fn arm_signal_timer(
        &mut self,
        _: carrick_guest_arch::Deadline,
    ) -> Result<(), NativeProcessError> {
        Ok(())
    }
    fn signal_now(&mut self) -> Result<carrick_guest_arch::CounterTick, NativeProcessError> {
        if let Some(mut hook) = self.on_signal_clock.take() {
            hook();
        }
        let now = if self.zone.counters.el1_timeouts.load(Ordering::Acquire) == 0 {
            1000
        } else {
            2000
        };
        Ok(carrick_guest_arch::CounterTick::new(now))
    }
    fn quarantine_prepared(&mut self, _: Self::PreparedMm) {
        panic!("unexpected quarantine")
    }
    fn quarantine_fork(&mut self, _: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm, C>) {
        panic!("unexpected fork quarantine")
    }
    fn quarantine_born(&mut self, _: Self::Born) {
        panic!("unexpected quarantine")
    }
    fn retire_mm(&mut self, _: Self::Mm) {}
    fn wake_effects(&mut self, effects: WakeEffects) {
        // Parent notification may request an SGI; the child's private
        // futex waiter is the only queued-on-this-slot wake in this test.
        if effects.queued_own {
            self.tid_wakes += 1;
        }
    }
    fn request_ingress_producer_boundary(&mut self) {}
}
pub fn words(address: AddressContext<RootGpa>) -> ParkedContextWords {
    let mut frame = [0; 20];
    frame[15] = 0x400000;
    frame[16] = 0x23;
    frame[17] = 0x202;
    frame[18] = 0x800000;
    frame[19] = 0x1b;
    ParkedContextWords::from_parts(
        frame,
        address,
        0x9000,
        0,
        [0; carrick_sched_core::X86_XSAVE_BYTES],
    )
}

/// A real native owner with aligned zone storage for cross-crate host tests.
/// Only physical memory operations are replaced by this host-test service;
/// registration, ingress drain, pending selection and frame delivery run
/// through the same production methods as the guest image.
pub struct NativeSignalFixture {
    zone: &'static ZoneTables<ParkedContextWords>,
    registry: &'static NativeProcessRegistry<'static, AddressContext<RootGpa>, ParkedContextWords>,
    runtime: Arc<NativeProcessRuntime<'static, AddressContext<RootGpa>, ParkedContextWords>>,
    task: &'static CurrentTask,
    control: &'static ThreadControlSlot,
    #[cfg(test)]
    page: &'static ThreadLifecyclePage,
    child_page: &'static ThreadLifecyclePage,
    child_controls: &'static [ThreadControlSlot; 9],
    address: AddressContext<RootGpa>,
    slot: SlotId,
    record: RecordRef,
    handler_signum: core::sync::atomic::AtomicI32,
}

impl Drop for NativeSignalFixture {
    fn drop(&mut self) {
        // The registry's member and group rows retain the signal owner even
        // after the fixture's runtime handle is dropped.
        let process = self.runtime.graph.lock().root_key;
        self.registry.unregister_process(&self.runtime, process);
    }
}

impl NativeSignalFixture {
    pub fn new(
        binding: ExecutionBinding,
        process: carrick_core_abi::EntryTaskKey,
        process_birth: carrick_core_abi::BirthSerial,
    ) -> Self {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: one aligned allocation owns this zero-valid compact zone for
        // the entire leaked host-test fixture lifetime.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            Box::leak(Box::from_raw(ptr))
        };
        let page = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let control = Box::leak(Box::new(ThreadControlSlot::new()));
        let child_page = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let child_controls =
            Box::leak(Box::new(core::array::from_fn(|_| ThreadControlSlot::new())));
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
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                task,
                page,
                control,
                address,
                address,
                words(address),
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
            #[cfg(test)]
            page,
            child_page,
            child_controls,
            address,
            slot,
            record,
            handler_signum: core::sync::atomic::AtomicI32::new(2),
        }
    }

    pub fn record(&self) -> RecordRef {
        self.record
    }

    pub fn control_slot(&self) -> &ThreadControlSlot {
        self.control
    }

    fn service(&self) -> Physical<'static> {
        Physical {
            zone: self.zone,
            page: self.child_page,
            controls: self.child_controls,
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            child_copy_error: None,
            refuse_copy: false,
            on_signal_clock: None,
        }
    }

    pub fn install_sigint_handler(&self, restart: bool) {
        self.install_handler(2, restart);
    }

    pub fn install_handler(&self, signum: i32, restart: bool) {
        use carrick_personality_linux::signal::ProcessSignals;
        self.handler_signum.store(signum, Ordering::Release);
        let mut service = self.service();
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                BornInZoneSource {
                    zone: self.zone,
                    slot: self.slot,
                },
                self.task,
                self.address,
                &words(self.address),
                &mut service,
            )
            .unwrap();
        entry
            .rt_sigaction(
                carrick_signal_core::policy::Signal::from_number(signum).unwrap(),
                Some(carrick_signal_core::policy::Action {
                    disposition: carrick_signal_core::policy::Disposition::Handler(
                        carrick_signal_core::policy::HandlerAddress(0x7000),
                    ),
                    flags: carrick_signal_core::policy::ActionFlags {
                        restart,
                        ..Default::default()
                    },
                    restorer: Some(carrick_signal_core::policy::RestorerAddress(0x8000)),
                    ..Default::default()
                }),
            )
            .unwrap();
    }

    pub fn ignore_signal(&self, signum: i32) {
        use carrick_personality_linux::signal::ProcessSignals;
        self.handler_signum.store(0, Ordering::Release);
        let mut service = self.service();
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                BornInZoneSource {
                    zone: self.zone,
                    slot: self.slot,
                },
                self.task,
                self.address,
                &words(self.address),
                &mut service,
            )
            .unwrap();
        entry
            .rt_sigaction(
                carrick_signal_core::policy::Signal::from_number(signum).unwrap(),
                Some(carrick_signal_core::policy::Action {
                    disposition: carrick_signal_core::policy::Disposition::Ignore,
                    ..Default::default()
                }),
            )
            .unwrap();
    }

    pub fn registry_signal_checkpoint_needed(&self) -> bool {
        self.registry
            .signal_checkpoint_needed(self.zone, self.record)
    }

    pub fn set_blocked_mask(&self, mask: carrick_personality_linux::abi::thread::BlockedMask) {
        let _ = self
            .control
            .store_blocked_then_read_pending(mask, self.control.pending());
    }

    pub fn drain_and_steal_on_sibling(
        &self,
        queue: &carrick_el1_abi::SharedSignalIngressQueue,
    ) -> (usize, bool) {
        let mut service = self.service();
        let drained = self
            .registry
            .drain_external_ingress(self.zone, queue, self.slot, &mut service)
            .unwrap();
        let signals = self.runtime.current_signals(self.task).unwrap();
        let sibling_record = RecordRef {
            id: carrick_sched_core::RecordId::from_raw(self.record.id.raw() + 1).unwrap(),
            incarnation: 1,
        };
        let stolen = signals
            .take_deliverable(
                sibling_record,
                carrick_signal_core::policy::SigBlockMask::NONE,
            )
            .is_some();
        (drained, stolen)
    }

    pub fn enqueue_process_signal_and_steal_on_sibling(&self, signum: i32) -> bool {
        let signals = self.runtime.current_signals(self.task).unwrap();
        let process_key = self
            .registry
            .state
            .lock()
            .members
            .values()
            .next()
            .unwrap()
            .process;
        let signal = carrick_signal_core::policy::Signal::from_number(signum).unwrap();
        signals.enqueue(process_key, signal, None).unwrap();
        let sibling_record = RecordRef {
            id: carrick_sched_core::RecordId::from_raw(self.record.id.raw() + 1).unwrap(),
            incarnation: 1,
        };
        signals
            .take_deliverable(
                sibling_record,
                carrick_signal_core::policy::SigBlockMask::NONE,
            )
            .is_some()
    }

    pub fn drain_and_deliver(
        &self,
        queue: &carrick_el1_abi::SharedSignalIngressQueue,
        frame: &mut carrick_el1_abi::TrapFrame,
    ) -> (
        usize,
        Option<carrick_personality_linux::dispatch::CompletionRoute>,
    ) {
        use zerocopy::IntoBytes;
        let mut service = self.service();
        let drained = self
            .registry
            .drain_external_ingress(self.zone, queue, self.slot, &mut service)
            .unwrap();
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                BornInZoneSource {
                    zone: self.zone,
                    slot: self.slot,
                },
                self.task,
                self.address,
                &words(self.address),
                &mut service,
            )
            .unwrap();
        assert!(
            !self.task.linux.has_pending_host_work(),
            "host work blocks signal delivery"
        );
        let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
        );
        let deliverable = self
            .runtime
            .current_signals(self.task)
            .unwrap()
            .has_deliverable(self.record, blocked);
        assert_eq!(
            entry.signal_checkpoint_needed(),
            drained != 0 || deliverable || self.control.forwarded_wait_mask_armed(),
            "native checkpoint must match admitted signal work"
        );
        let signum = self.handler_signum.load(Ordering::Acquire);
        if signum != 0 {
            assert!(matches!(
                carrick_personality_linux::signal::ProcessSignals::rt_sigaction(
                    &mut *entry,
                    carrick_signal_core::policy::Signal::from_number(signum).unwrap(),
                    None,
                )
                .unwrap()
                .disposition,
                carrick_signal_core::policy::Disposition::Handler(_)
            ));
        }
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let mut machine = HostArmSignalMachine {
            backend: HostArmBackend,
        };
        let route = crate::signal_delivery::deliver_signal_with_control(
            self.task,
            self.control,
            &mut entry,
            frame,
            fp.as_bytes(),
            &mut machine,
        );
        (drained, route)
    }
}

struct HostArmSignalMachine {
    backend: HostArmBackend,
}
impl crate::signal_delivery::SignalMachine<ParkedContextWords> for HostArmSignalMachine {
    type Backend = HostArmBackend;

    fn backend(&mut self) -> &mut Self::Backend {
        &mut self.backend
    }
    fn user_sp(&self, _: &carrick_el1_abi::TrapFrame) -> UserVa {
        UserVa::new(0x400000)
    }
    fn restart(&self, _: &mut carrick_el1_abi::TrapFrame, _: &ParkedContextWords) -> bool {
        false
    }
    fn restart_forwarded(&self, frame: &mut carrick_el1_abi::TrapFrame) -> Option<bool> {
        crate::arm_signal::restart_forwarded_frame(frame)
    }
    fn group_exit_custody(
        &self,
        _: &CurrentTask,
    ) -> carrick_personality_linux::dispatch::CompletionRoute {
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
    }
}

struct HostArmBackend;
impl carrick_guest_arch::ArchTypes for HostArmBackend {
    type Error = carrick_el1::isa::ArchError;
    type NativeFrame = carrick_el1_abi::TrapFrame;
    type SavedContext = carrick_el1_abi::ThreadCtx;
    type Context = carrick_el1_abi::ThreadCtx;
    type Root = RootGpa;
    type MmOwner = CurrentTask;
    type DrainTicket = ();
    type DrainReceipt = ();
    type UserTransfer = ();
    type HardwareInterrupt = ();
    type InterruptMask = ();
}
impl carrick_personality_linux::signal::SignalBackend for HostArmBackend {
    fn setup_signal_frame(
        &mut self,
        frame: &mut carrick_el1_abi::TrapFrame,
        params: carrick_personality_linux::signal::SignalFrameParams,
        siginfo: Option<&[u8]>,
        fpstate: &[u8],
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, Self::Error> {
        crate::arm_signal::setup_arm_signal_frame(frame, params, siginfo, fpstate, copy_out)
    }

    fn restore_signal_frame(
        &mut self,
        _frame: &mut carrick_el1_abi::TrapFrame,
        _fpstate: &mut [u8],
        _copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, Self::Error> {
        Err(carrick_el1::isa::ArchError::Unbound)
    }
}

pub fn empty_signal_checkpoint_lock_witness() {
    use carrick_core_abi::{
        BirthSerial, EntryMmKey, EntryTaskKey, EntryThreadGeneration, SnapshotGeneration,
    };
    let binding = ExecutionBinding {
        task: EntryTaskKey::from_raw(123_450),
        generation: SnapshotGeneration::from_raw(11),
        mm: EntryMmKey::from_raw(1),
        thread_generation: EntryThreadGeneration::from_raw(101),
    };
    let fixture = NativeSignalFixture::new(
        binding,
        EntryTaskKey::from_raw(123_450),
        BirthSerial::of_task(carrick_sched_core::process::TaskSerial::from_raw_u64(5).unwrap()),
    );
    let registry_guard = fixture.registry.state.lock();
    let graph_guard = fixture.runtime.graph.lock();
    std::thread::scope(|scope| {
        let (send, receive) = std::sync::mpsc::channel();
        let fixture = &fixture;
        scope.spawn(move || {
            let needed = fixture
                .registry
                .signal_checkpoint_needed(fixture.zone, fixture.record);
            let _ = send.send(needed);
        });
        let without_locks = receive.recv_timeout(std::time::Duration::from_secs(5)).ok();
        drop(graph_guard);
        drop(registry_guard);
        assert_eq!(
            without_locks,
            Some(false),
            "empty IRQ checkpoint acquired an owner lock"
        );
    });

    let signal = carrick_signal_core::policy::Signal::from_number(10).unwrap();
    fixture
        .control
        .init_blocked(carrick_el1_abi::BlockedMask(signal.bit()));
    let signals = fixture.runtime.current_signals(fixture.task).unwrap();
    let process = fixture.runtime.graph.lock().root_key;
    signals.enqueue(process, signal, None).unwrap();
    let registry_guard = fixture.registry.state.lock();
    let graph_guard = fixture.runtime.graph.lock();
    std::thread::scope(|scope| {
        let (send, receive) = std::sync::mpsc::channel();
        let fixture = &fixture;
        scope.spawn(move || {
            let needed = fixture
                .registry
                .signal_checkpoint_needed(fixture.zone, fixture.record);
            let _ = send.send(needed);
        });
        let without_locks = receive.recv_timeout(std::time::Duration::from_secs(5)).ok();
        drop(graph_guard);
        drop(registry_guard);
        assert_eq!(
            without_locks,
            Some(false),
            "blocked pending signal acquired an owner lock"
        );
    });
    fixture
        .control
        .init_blocked(carrick_el1_abi::BlockedMask(0));
    assert!(
        fixture
            .registry
            .signal_checkpoint_needed(fixture.zone, fixture.record)
    );
    // Leave work pending: fixture teardown must release its signal owner so
    // the next empty checkpoint can use the process-global summary fast path.
}

/// Production native signal/terminal owner attached to a host test's retained
/// kernel lifecycle and zone. Only physical memory service is substituted.
pub struct NativeOwnerSignalFixture {
    zone: &'static ZoneTables<carrick_sched_core::Aarch64ParkedContext>,
    registry: &'static NativeProcessRegistry<
        'static,
        AddressContext<RootGpa>,
        carrick_sched_core::Aarch64ParkedContext,
    >,
    runtime: Arc<
        NativeProcessRuntime<
            'static,
            AddressContext<RootGpa>,
            carrick_sched_core::Aarch64ParkedContext,
        >,
    >,
    page: &'static ThreadLifecyclePage,
    root: &'static CurrentTask,
    root_control: &'static ThreadControlSlot,
    address: AddressContext<RootGpa>,
    words: carrick_sched_core::Aarch64ParkedContext,
    members: Vec<(
        &'static CurrentTask,
        SlotId,
        carrick_sched_core::Aarch64ParkedContext,
    )>,
}
impl Drop for NativeOwnerSignalFixture {
    fn drop(&mut self) {
        let process = self.runtime.graph.lock().root_key;
        self.registry.unregister_process(&self.runtime, process);
    }
}
impl NativeOwnerSignalFixture {
    #[allow(clippy::too_many_arguments)]
    fn install(
        zone: &'static ZoneTables<carrick_sched_core::Aarch64ParkedContext>,
        binding: ExecutionBinding,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        file_table: u64,
        slot: SlotId,
        words: carrick_sched_core::Aarch64ParkedContext,
        pid: u32,
    ) -> &'static CurrentTask {
        let address = words.address_context().unwrap();
        let task = Box::leak(Box::new(CurrentTask::new()));
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(binding.task.raw() as i32),
            binding.generation,
            file_table,
        );
        task.mm.key.store(binding.mm.raw(), Ordering::Release);
        task.mm
            .thread_generation
            .store(binding.thread_generation.raw(), Ordering::Release);
        task.publish_visible_pid(pid);
        task.publish_root_generation(address.generation);
        task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 1, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, binding.mm.raw()).unwrap();
        let record = zone
            .current_or_new(
                slot,
                ThreadIdentity {
                    tid: binding.task.raw(),
                    serial: binding.thread_generation.raw(),
                    mm: binding.mm.raw(),
                    file_table,
                    generation: binding.generation.raw(),
                    affinity_source: control.affinity_source(),
                    affinity: 1,
                    lifecycle_page: page as *const _ as u64,
                    control_slot: control as *const _ as u64,
                },
            )
            .unwrap();
        control.bind_zone_record(zone.record_ref(record));
        // The physical test service is a stopped host venue. Publishing a
        // running vCPU here would route host continuations into an undriven
        // guest service queue instead of their registered executor.
        zone.leave_guest(slot, &carrick_sched_core::ShortLockSpin);
        assert!(zone.step_away(
            slot,
            1,
            &mut |_| panic!("fresh host fixture has no queued handback"),
            &mut |_| panic!("fresh host fixture has no displaced placement")
        ));
        task
    }
    pub fn new<B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
        zone: &'static ZoneTables<carrick_sched_core::Aarch64ParkedContext>,
        binding: ExecutionBinding,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        file_table: u64,
        words: carrick_sched_core::Aarch64ParkedContext,
    ) -> Self {
        let address = words.address_context().unwrap();
        let slot = SlotId::new(0);
        let root = Self::install(
            zone,
            binding,
            page,
            control,
            file_table,
            slot,
            words,
            control.visible_tid().unwrap(),
        );
        zone.mm_issuer().observe_existing(address.mm);
        zone.serial_issuer()
            .advance_past(NonZeroU64::new(binding.thread_generation.raw()).unwrap());
        zone.serial_issuer().advance_past(
            NonZeroU64::new(control.host_birth_identity().unwrap().birth().raw()).unwrap(),
        );
        let runtime = Arc::new(
            NativeProcessRuntime::admit_fresh_root::<B>(
                BornInZoneSource { zone, slot },
                root,
                page,
                control,
                address,
                address,
                words,
            )
            .unwrap(),
        );
        let registry = Box::leak(Box::new(NativeProcessRegistry::new()));
        registry
            .register_root(
                runtime.clone(),
                BornInZoneSource { zone, slot },
                root,
                address,
            )
            .unwrap();
        Self {
            zone,
            registry,
            runtime,
            page,
            root,
            root_control: control,
            address,
            words,
            members: Vec::new(),
        }
    }
    pub fn add_sibling(
        &mut self,
        binding: ExecutionBinding,
        control: &'static ThreadControlSlot,
        words: carrick_sched_core::Aarch64ParkedContext,
    ) {
        let slot = SlotId::new(u8::try_from(1 + self.members.len()).unwrap());
        let task = Self::install(
            self.zone,
            binding,
            self.page,
            control,
            self.root.linux.file_table.load(Ordering::Acquire),
            slot,
            words,
            self.root.visible_pid().unwrap(),
        );
        self.registry
            .register_thread(
                BornInZoneSource {
                    zone: self.zone,
                    slot,
                },
                task,
                self.address,
                self.page,
                control,
            )
            .unwrap();
        self.members.push((task, slot, words));
    }
    fn physical(&self) -> Physical<'static, carrick_sched_core::Aarch64ParkedContext> {
        Physical {
            zone: self.zone,
            page: self.page,
            controls: &[],
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            child_copy_error: None,
            refuse_copy: false,
            on_signal_clock: None,
        }
    }
    pub fn kill_from_sibling(&self) -> Option<carrick_el1_abi::HostWorkDoorbell> {
        self.signal_from_sibling(false)
    }
    pub fn tgkill_from_sibling(&self) -> Option<carrick_el1_abi::HostWorkDoorbell> {
        self.signal_from_sibling(true)
    }
    fn signal_from_sibling(
        &self,
        thread_directed: bool,
    ) -> Option<carrick_el1_abi::HostWorkDoorbell> {
        use carrick_personality_linux::signal::{
            ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
        };
        let (task, slot, words) = *self.members.last().unwrap();
        let mut physical = self.physical();
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                BornInZoneSource {
                    zone: self.zone,
                    slot,
                },
                task,
                self.address,
                &words,
                &mut physical,
            )
            .unwrap();
        let request = SignalRequest::Deliver(carrick_signal_core::policy::Signal::KILL);
        let info = SignalInfo::Generated(None);
        if thread_directed {
            use carrick_personality_linux::signal::SignalThreadSelector;
            entry
                .tgkill(
                    SignalThreadSelector::from_abi(self.root.visible_pid().unwrap() as u64),
                    SignalThreadSelector::from_abi(self.root_control.visible_tid().unwrap() as u64),
                    request,
                    info,
                )
                .unwrap();
        } else {
            entry
                .kill(
                    SignalProcessSelector::from_abi(self.root.visible_pid().unwrap() as u64),
                    request,
                    info,
                )
                .unwrap();
        }
        task.linux.take_host_work_doorbell()
    }
    pub fn cancel_root(&self) {
        let mut physical = self.physical();
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                BornInZoneSource {
                    zone: self.zone,
                    slot: SlotId::new(0),
                },
                self.root,
                self.address,
                &self.words,
                &mut physical,
            )
            .unwrap();
        assert!(matches!(
            entry.cancel_owner_wait().unwrap(),
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
        assert!(self.page.process_exit_custody().caller_reserved());
        assert!(entry.take_handoff_receipt().is_some());
    }
}

/// Real native fork/service ownership for host executor-capacity tests. Only
/// physical MM operations use `Physical`; no child receives a host task binding.
pub struct NativeServiceCapacityFixture {
    fixture: NativeSignalFixture,
    pending: Vec<
        carrick_core_abi::service::ServiceTicket<&'static carrick_core_abi::service::ServiceCell>,
    >,
    children: usize,
}

impl NativeServiceCapacityFixture {
    pub fn new(children: usize) -> Self {
        let fixture = NativeSignalFixture::new(
            ExecutionBinding {
                task: carrick_core_abi::EntryTaskKey::from_raw(7001),
                generation: carrick_core_abi::SnapshotGeneration::INITIAL,
                mm: carrick_core_abi::EntryMmKey::from_raw(1),
                thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(1),
            },
            carrick_core_abi::EntryTaskKey::from_raw(7001),
            carrick_core_abi::BirthSerial::of_task(TaskSerial::from_registry_allocation(
                NonZeroU64::MIN,
            )),
        );
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        for _ in 0..children {
            // Every process birth has its own lifecycle owner, just as the
            // production fork stock does. Sharing one page hides exit bugs.
            let mut service = fixture.service();
            service.page = Box::leak(Box::new(ThreadLifecyclePage::new()));
            service.controls = Box::leak(Box::new(core::array::from_fn::<_, 9, _>(|_| {
                ThreadControlSlot::new()
            })));
            let mut entry = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    source,
                    fixture.task,
                    fixture.address,
                    &words(fixture.address),
                    &mut service,
                )
                .unwrap();
            assert!(
                matches!(entry.fork(ProcessForkChildTid::NONE), LifecycleOutcome::Returned { result, .. } if result.raw() > 0)
            );
        }
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.wait4(
                ProcessWaitPid::from_syscall_argument(u64::MAX),
                UserVa::new(0),
                LinuxWaitOptions::empty(),
                UserVa::new(0),
            ),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_handoff_receipt().is_some());
        drop(entry);
        Self {
            fixture,
            pending: Vec::new(),
            children,
        }
    }

    fn select(&self) -> Option<(RecordRef, AddressContext<RootGpa>, ParkedContextWords)> {
        let fixture = &self.fixture;
        let selected = fixture.zone.switch_in_full(fixture.slot)?;
        let record = fixture.zone.record_ref(selected.record);
        let identity = fixture.zone.record(selected.record).identity();
        let key = fixture
            .registry
            .state
            .lock()
            .members
            .values()
            .find(|member| member.record == record)
            .unwrap()
            .process;
        let address = fixture.runtime.task_binding(key).unwrap().address;
        fixture
            .zone
            .install_space(fixture.slot, identity.mm)
            .unwrap();
        fixture.task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(identity.tid as i32),
            carrick_core_abi::SnapshotGeneration::from_raw(identity.generation),
            identity.file_table,
        );
        fixture.task.mm.key.store(identity.mm, Ordering::Release);
        fixture
            .task
            .mm
            .thread_generation
            .store(identity.serial, Ordering::Release);
        fixture.task.publish_visible_pid(key.id.raw() as u32);
        fixture
            .task
            .publish_lifecycle(identity.lifecycle_page, identity.control_slot);
        // SAFETY: the selected exact record is OnCpu on the fixture's only slot.
        Some((record, address, unsafe {
            *fixture.zone.record(selected.record).ctx_mut()
        }))
    }

    /// One guest idle quantum. The caller retains no execution capacity after
    /// this returns; all outstanding tickets remain owned by this fixture.
    pub fn park_next(&mut self) -> Option<usize> {
        use carrick_core_abi::service::{ServiceCell, ServiceOperation};
        let (record, address, words) = self.select()?;
        let fixture = &self.fixture;
        assert!(fixture.zone.record(record.id).is_native_owned());
        let identity = fixture.zone.record(record.id).identity();
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
                address,
                &words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.resume_checkpoint().unwrap(),
            NativeResume::NoPending
        ));
        assert!(matches!(
            entry
                .begin_service(
                    ServiceOperation::CarrierWork {
                        entry: carrick_sched_core::object_wait::OwnerEntry::Syscall,
                    },
                    None
                )
                .unwrap(),
            NativeResume::Left(None)
        ));
        assert!(entry.take_handoff_receipt().is_some());
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap(),
                &carrick_sched_core::ShortLockSpin,
            )
            .unwrap();
        assert_eq!(queue.native_service_member(record), Some(identity));
        // SAFETY: the real native owner retains this exact control allocation;
        // the service queue authenticates the notice and excludes cancellation.
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        let ticket = unsafe {
            ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, identity)
        }
        .unwrap();
        self.pending.push(ticket);
        Some(self.pending.len())
    }

    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }

    pub fn acknowledge_and_retire(&mut self) {
        assert_eq!(self.pending.len(), self.children);
        let fixture = &self.fixture;
        for ticket in self.pending.drain(..) {
            let record = ticket.request().identity.birth.record;
            let queue = fixture
                .zone
                .object_wait(
                    carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap(),
                    &carrick_sched_core::ShortLockSpin,
                )
                .unwrap();
            assert!(ticket.complete(true).is_ok());
            queue
                .notify_object(fixture.slot, &mut WakeEffects::default())
                .unwrap();
        }
        for _ in 0..self.children {
            let (record, address, words) = self.select().unwrap();
            let fixture = &self.fixture;
            assert!(fixture.zone.record(record.id).is_native_owned());
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
                    address,
                    &words,
                    &mut service,
                )
                .unwrap();
            assert!(matches!(
                entry.resume_checkpoint().unwrap(),
                NativeResume::NoPending
            ));
            let waiting = fixture.runtime.graph.lock().has_member_wait(&record);
            assert!(!waiting);
            assert!(matches!(
                entry.exit_group(0),
                LifecycleOutcome::Transferred { .. }
            ));
        }
    }
}

#[cfg(test)]
fn native_exec_fixture() -> NativeSignalFixture {
    NativeSignalFixture::new(
        ExecutionBinding {
            task: carrick_core_abi::EntryTaskKey::from_raw(41),
            generation: carrick_core_abi::SnapshotGeneration::from_raw(11),
            mm: carrick_core_abi::EntryMmKey::from_raw(1),
            thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(101),
        },
        carrick_core_abi::EntryTaskKey::from_raw(41),
        carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(11).unwrap()),
    )
}

#[cfg(test)]
fn publish_test_exec_reply(
    fixture: &NativeSignalFixture,
    receipt_raw: u64,
    root_raw: u64,
) -> carrick_core_abi::ReservationMm {
    use carrick_core_abi::service::{
        ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
        ServiceCell,
    };
    use carrick_guest_arch::{Asid, UserVa};
    use carrick_sched_core::object_wait::ObjectWaitKey;
    use core::num::NonZeroU16;

    let selector = fixture.task.service_notice.take().unwrap().unwrap();
    let key = ObjectWaitKey::native_service(selector.record).unwrap();
    let queue = fixture
        .zone
        .object_wait(key, &carrick_sched_core::ShortLockSpin)
        .unwrap();
    let member = queue.native_service_member(selector.record).unwrap();
    // SAFETY: this test owns the announced exact service member and consumes
    // its ticket once before releasing the queue.
    let ticket = unsafe {
        ServiceCell::claim_notice(&fixture.control.service, selector, NonZeroU64::MIN, member)
    }
    .unwrap();
    let request = ticket.request();
    let manifest_address = ticket.reply_address().unwrap();
    // SAFETY: the ring retains this aligned reply record until acknowledgment.
    let manifest = unsafe { &mut *(manifest_address.raw() as *mut ExecSuccessorManifest) };
    let successor_mm = manifest.proposal(request.identity).unwrap();
    let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(receipt_raw).unwrap()).unwrap();
    *manifest = manifest
        .seal(
            request.identity,
            receipt,
            ExecSuccessorBacking {
                root: RootGpa::page_aligned(FrameGpa::new(root_raw)).unwrap(),
                root_generation: NonZeroU64::new(receipt_raw + 6).unwrap(),
                asid: Asid::from_registry_allocation(
                    NonZeroU16::new(u16::try_from(receipt_raw + 12).unwrap()).unwrap(),
                ),
                asid_generation: NonZeroU64::new(receipt_raw + 14).unwrap(),
            },
            ExecSuccessorEntry {
                entry: UserVa::new(0x40_0000),
                stack_pointer: UserVa::new(0x7fff_f000),
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
    drop(queue);
    let mut service = fixture.service();
    service.wake_effects(effects);
    successor_mm
}

#[cfg(test)]
struct ExecSibling {
    task: &'static CurrentTask,
    control: &'static ThreadControlSlot,
    slot: SlotId,
    record: RecordRef,
    _wait: Option<Arc<WaitChannel>>,
}

#[cfg(test)]
fn add_exec_sibling(fixture: &NativeSignalFixture, parked_read: bool) -> ExecSibling {
    let binding = ExecutionBinding {
        task: carrick_core_abi::EntryTaskKey::from_raw(42),
        generation: carrick_core_abi::SnapshotGeneration::from_raw(12),
        mm: carrick_core_abi::EntryMmKey::from_raw(1),
        thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(102),
    };
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    control
        .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
        .unwrap();
    assert!(control.publish_visible_tid(42));
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            binding.task,
            carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(12).unwrap()),
            binding.thread_generation,
        )
        .unwrap(),
    );
    let birth = fixture.page.reserve_host_birth().unwrap();
    carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
    assert!(
        fixture
            .page
            .publish_host_birth(birth, control.host_birth_identity().unwrap())
    );

    let task = Box::leak(Box::new(CurrentTask::new()));
    task.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(42),
        binding.generation,
        5,
    );
    task.mm.key.store(1, Ordering::Release);
    task.mm.thread_generation.store(102, Ordering::Release);
    task.publish_visible_pid(41);
    task.publish_root_generation(fixture.address.generation);
    task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    let slot = SlotId::new(1);
    fixture.zone.drive(slot, 2);
    fixture.zone.publish_slot(slot, 1, Some(1), 1);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, 1).unwrap();
    let record = fixture
        .zone
        .current_or_new(
            slot,
            ThreadIdentity {
                tid: 42,
                serial: 102,
                mm: 1,
                file_table: 5,
                generation: 12,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();
    let record = fixture.zone.record_ref(record);
    control.bind_zone_record(record);
    fixture
        .registry
        .register_thread(
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            task,
            fixture.address,
            fixture.page,
            control,
        )
        .unwrap();

    let wait = parked_read.then(|| {
        let wait = Arc::new(WaitChannel {
            generation: ProcessWake::new(),
            mm: 1,
        });
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot,
        };
        let start = carrick_core::entry::prepare_handoff(binding, source, record.id).unwrap();
        let address = WaitChannel::address(&wait);
        let guard = fixture.zone.short_lock(
            ZoneTables::<ParkedContextWords>::bucket_of_with_context(1, address),
            &NativeBucketWait {
                lifetime: core::marker::PhantomData,
                probe: None,
            },
        );
        let sequence = fixture.zone.next_seq(record.id);
        fixture
            .zone
            .enqueue(&guard, record.id, sequence, 1, address, u32::MAX, 0)
            .unwrap();
        // SAFETY: this fixture owns the sibling's selected record until the
        // owned read continuation below publishes its handoff.
        unsafe {
            *fixture.zone.record(record.id).ctx_mut() = words(fixture.address);
            fixture
                .zone
                .record(record.id)
                .publish_owner_continuation(OwnerEntry::Syscall);
        }
        assert!(
            carrick_core::entry::publish_handoff_park(
                start,
                &guard,
                carrick_el1_abi::EntryRecordGeneration(sequence),
            )
            .is_some()
        );
        drop(guard);
        fixture.zone.clear_current(slot);
        wait
    });

    ExecSibling {
        task,
        control,
        slot,
        record,
        _wait: wait,
    }
}

#[test]
fn native_exec_successor_runs_after_consuming_the_prepared_receipt() {
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let graph = fixture.runtime.graph.lock();
        let page = graph
            .owner
            .task(graph.root_key)
            .unwrap()
            .native()
            .resources()
            .page;
        assert!(
            page.gate().serves_ring(),
            "exec fixture gate: {:?}",
            page.gate()
        );
        assert!(!graph.has_member_wait(&fixture.record));
    }
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        let result = entry.begin_exec_service(Box::from(&b"/bin/static\0\0\0"[..]));
        match result {
            Ok(NativeResume::Left(None)) => {}
            Ok(_) => panic!("exec intake returned the wrong continuation"),
            Err(error) => panic!("exec intake failed: {error:?}"),
        }
        assert!(entry.take_handoff_receipt().is_some());
    }

    let successor_mm = publish_test_exec_reply(&fixture, 47, 0x90_0000);

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    // SAFETY: `switch_in_full` handed this exact selected record to the test
    // lane, which retains it until the entry below consumes the continuation.
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
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
    let resumed = entry.resume_checkpoint();
    assert!(matches!(resumed, Ok(NativeResume::NoPending)));
    assert_eq!(
        entry.calling_tid(),
        41,
        "successor's first syscall keeps leader tid"
    );
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        successor_mm.raw()
    );
    assert_eq!(
        fixture.zone.installed_space(fixture.slot),
        successor_mm.raw()
    );
    assert!(fixture.zone.spaces.find(1).is_none());
}

#[cfg(test)]
fn exec_after_sibling_drain(parked_read: bool) {
    let fixture = native_exec_fixture();
    let sibling = add_exec_sibling(&fixture, parked_read);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.begin_exec_service(Box::from(&b"/bin/static\0\0\0"[..])),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let successor_mm = publish_test_exec_reply(&fixture, 71, 0xa0_0000);

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    // SAFETY: the root record was selected by this lane and remains retained
    // until `resume_checkpoint` publishes the owned exec-drain continuation.
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
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
            entry.resume_checkpoint(),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_none());
    }
    assert!(sibling.control.host_exit_requested());
    assert!(fixture.zone.slot(fixture.slot).current().is_none());

    // The host withdraws the exact sibling before publishing its receipt.
    // A running sibling reaches this boundary from its next EL0 exit; an
    // owned blocking-read continuation is cancelled without reacquiring a
    // guest execution lane.
    if !parked_read {
        fixture
            .zone
            .leave_guest(sibling.slot, &carrick_sched_core::ShortLockSpin);
    }
    let _ = fixture.zone.claim_for_host(
        sibling.record,
        None,
        carrick_el1_abi::Handback::Cancelled,
        &carrick_sched_core::ShortLockSpin,
    );
    fixture
        .page
        .reserve_cancelled_member_exit()
        .unwrap()
        .publish();
    fixture.page.publish_exact_host_retirement(
        sibling.control,
        sibling.control.host_birth_identity().unwrap().retirement(),
    );

    let (mm, address) = fixture.page.exit_wait().unwrap();
    let guard = fixture
        .zone
        .lock(
            ZoneTables::<ParkedContextWords>::bucket_of_with_context(mm.raw(), address),
            &carrick_sched_core::ShortLockSpin,
        )
        .unwrap();
    let mut transfers = Vec::new();
    let woken = fixture.zone.wake_host(
        &guard,
        mm.raw(),
        address,
        u32::MAX,
        u32::MAX,
        true,
        &mut |transfer| transfers.push(transfer),
        &mut |_| {},
    );
    drop(guard);
    assert_eq!(woken, 1);
    assert!(transfers.is_empty());

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    let resumed_runtime = fixture
        .registry
        .for_entry(source, fixture.task, fixture.address)
        .unwrap();
    assert!(Arc::ptr_eq(&resumed_runtime, &fixture.runtime));
    // SAFETY: the exit wait selected the retained root continuation exactly
    // once; the entry consumes it below.
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
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
    let resumed = entry.resume_checkpoint();
    assert!(matches!(resumed, Ok(NativeResume::NoPending)));
    assert_eq!(entry.calling_tid(), 41);
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        successor_mm.raw()
    );
    assert!(fixture.zone.slot(sibling.slot).current().is_none());
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .owner
            .task(entry.key)
            .unwrap()
            .native()
            .resources()
            .members
            .len()
            == 1
    );
    assert_eq!(sibling.task.mm.key.load(Ordering::Acquire), 1);
}

#[test]
fn native_exec_drains_a_spinning_sibling_without_reentering_el0() {
    exec_after_sibling_drain(false);
}

#[test]
fn native_exec_drains_a_sibling_parked_in_an_owned_read() {
    exec_after_sibling_drain(true);
}
