//! Host-only physical service for production native signal path witnesses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use carrick_guest_arch::{ContextGeneration, FrameGpa};
use carrick_sched_core::ParkedContextWords;

std::thread_local! {
    static SIGNAL_COPIES: std::cell::RefCell<Vec<(UserVa, Vec<u8>)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static EXEC_CANCELLATIONS: std::cell::RefCell<Vec<u64>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

pub fn take_signal_copies() -> Vec<(UserVa, Vec<u8>)> {
    SIGNAL_COPIES.with(|copies| core::mem::take(&mut *copies.borrow_mut()))
}

#[cfg(test)]
fn take_exec_cancellations() -> Vec<u64> {
    EXEC_CANCELLATIONS.with(|receipts| core::mem::take(&mut *receipts.borrow_mut()))
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
    pub prepare_copy_error: Option<NativeProcessError>,
    pub child_copy_error_at: Option<u64>,
    pub on_copy_complete: Option<Box<dyn FnMut(UserVa) + 'a>>,
    pub native_ipc: Option<carrick_el1_abi::ipc::IpcRegion<'a>>,
    pub refuse_copy: bool,
    pub on_signal_clock: Option<Box<dyn FnMut() + 'a>>,
}
struct HostExecSlot<'a, C: ProcessContext> {
    zone: &'a ZoneTables<C>,
    index: carrick_sched_core::SpaceIndex,
    mm: carrick_core_abi::ReservationMm,
    armed: bool,
}
impl<C: ProcessContext> ExecSuccessorSlot for HostExecSlot<'_, C> {
    fn mm(&self) -> carrick_core_abi::ReservationMm {
        self.mm
    }
    fn root_generation(&self) -> NonZeroU64 {
        NonZeroU64::MIN
    }
    fn prepare_adoption(&self) -> Result<carrick_core_abi::El1MmHandle, NativeProcessError> {
        // SAFETY: this VM-free token owns the exact synthetic closed MM.
        Ok(unsafe {
            carrick_core_abi::El1MmHandle::from_admitted_owner(
                NonZeroU64::MIN,
                self.mm,
                NonZeroU64::MIN,
            )
        })
    }
    fn commit(mut self: Box<Self>) {
        self.armed = false;
    }
}
impl<C: ProcessContext> Drop for HostExecSlot<'_, C> {
    fn drop(&mut self) {
        if self.armed {
            self.zone.spaces.free(self.index);
        }
    }
}
impl<'a, C: ProcessContext> NativeProcessService<'a, C> for Physical<'a, C> {
    type Mm = AddressContext<RootGpa>;
    type PreparedMm = AddressContext<RootGpa>;
    type Born = AddressContext<RootGpa>;
    fn prepare_exec_successor_slot(
        &self,
        mm: carrick_core_abi::ReservationMm,
    ) -> Result<Box<dyn ExecSuccessorSlot + 'a>, NativeProcessError> {
        let index = self
            .zone
            .spaces
            .publish_closed(mm.raw(), 0, 0)
            .ok_or(NativeProcessError::Exhausted)?;
        if !self.zone.spaces.mark_initial_bindable(index) {
            self.zone.spaces.free(index);
            return Err(NativeProcessError::Stale);
        }
        Ok(Box::new(HostExecSlot {
            zone: self.zone,
            index,
            mm,
            armed: true,
        }))
    }
    fn cancel_exec_successor(
        &self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
    ) -> Result<(), NativeProcessError> {
        EXEC_CANCELLATIONS.with(|receipts| receipts.borrow_mut().push(receipt.raw().get()));
        Ok(())
    }
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
        let index = self
            .zone
            .spaces
            .find(sealed.successor_mm.raw())
            .ok_or(NativeProcessError::Stale)?;
        if !self
            .zone
            .spaces
            .bind_initial_root(index, sealed.successor_mm.raw(), ttbr, ttbr)
        {
            return Err(NativeProcessError::Stale);
        }
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
        if address.raw() == 1 {
            return Err(NativeProcessError::Fault);
        }
        if let Some(error) = self.child_copy_error
            && self
                .child_copy_error_at
                .is_none_or(|at| address.raw() == at)
        {
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
        if let Some(hook) = &mut self.on_copy_complete {
            hook(address);
        }
        Ok(())
    }
    fn prepare_owned_write(
        &mut self,
        _: &Self::Mm,
        request: carrick_core::mm::transaction::CopyoutRequest,
    ) -> Result<(), NativeProcessError> {
        if let Some(error) = self.prepare_copy_error.or(self.child_copy_error)
            && self
                .child_copy_error_at
                .is_none_or(|at| request.address.raw() == at)
        {
            return Err(error);
        }
        if let Some(hook) = &mut self.on_copy_complete {
            hook(request.address);
        }
        Ok(())
    }
    fn retire_adapter_operation(
        &mut self,
        binding: ExecutionBinding,
        operation: carrick_sched_core::object_wait::OperationToken,
    ) -> Result<usize, NativeProcessError> {
        let region = self
            .native_ipc
            .as_ref()
            .ok_or(NativeProcessError::Unsupported)?;
        // This fixture's slot owns the same admitted root throughout the wait.
        let task = CurrentTask::new();
        crate::ipc::retire_native_operation(
            region,
            self.zone,
            SlotId::from_index(0).unwrap(),
            &task,
            binding,
            operation,
        )
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
        crate::sched::object_wait::deliver_wake_effects(self.zone, SlotId::new(0), effects);
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
            prepare_copy_error: None,
            child_copy_error_at: None,
            on_copy_complete: None,
            native_ipc: None,
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
        let route = crate::signal_delivery::deliver_signal_on_syscall_return(
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
            prepare_copy_error: None,
            child_copy_error_at: None,
            on_copy_complete: None,
            native_ipc: None,
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
        Self::from_fixture(fixture, children)
    }

    fn from_fixture(fixture: NativeSignalFixture, children: usize) -> Self {
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
                UserVa::new(0x1000),
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

    #[cfg(test)]
    fn after_root_exec(children: usize) -> Self {
        let mut fixture = NativeSignalFixture::new(
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
        let mut service = fixture.service();
        {
            let mut root = fixture
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
                root.begin_exec_service(test_exec_payload(b"/bin/static")),
                Ok(NativeResume::Left(None))
            ));
            assert!(root.take_handoff_receipt().is_some());
        }
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 211, 0x120_0000);
        let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
        assert_eq!(selected.record, fixture.record.id);
        let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
            .unwrap()
            .words;
        let root_key = fixture.runtime.graph.lock().root_key;
        let predecessor = fixture.runtime.task_binding(root_key).unwrap().address;
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                predecessor,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            root.resume_checkpoint(),
            Ok(NativeResume::NoPending)
        ));
        drop(root);
        fixture.address = fixture.runtime.task_binding(root_key).unwrap().address;
        assert!(
            fixture
                .registry
                .for_entry(source, fixture.task, fixture.address)
                .is_ok(),
            "successor registry lookup"
        );
        assert!(
            fixture
                .registry
                .for_record(fixture.zone, fixture.record)
                .is_some(),
            "successor record lookup"
        );
        Self::from_fixture(fixture, children)
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
                NativeResume::Returned(result)
                    if result.raw() == words.syscall_return() as i64
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
#[test]
fn carrier_work_wake_preserves_the_completed_syscall_result() {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_guest_arch::ProcessContext;

    const COMPLETED: u64 = 0x41;
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    let completed = words(fixture.address).with_syscall_return(COMPLETED);
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &completed,
                &mut service,
            )
            .unwrap();
        let result = entry.begin_service(
            ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
            },
            None,
        );
        assert!(matches!(
            entry.settle_service_exit(result, NativeServiceExit::CarrierWork),
            Ok(NativeResume::Left(None))
        ));
        // A native service token is not an IPC token/pin. Its ordinary
        // bridge refusal must retain main's outcome rather than gain a retry.
        assert!(matches!(
            entry.settle_service_exit(
                Err(NativeProcessError::Busy),
                NativeServiceExit::CarrierWork
            ),
            Err(NativeProcessError::Busy)
        ));
    }

    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
        )
        .unwrap();
    // SAFETY: the fixture retains the exact process control and record named
    // by this service notice until the completion is consumed below.
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(fixture.record.id).identity(),
        )
    }
    .unwrap();
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words
        .with_syscall_return(0);
    let mut resumed = fixture
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
        resumed.resume_checkpoint(),
        Ok(NativeResume::Returned(result)) if result.raw() == COMPLETED as i64
    ));
}

#[cfg(test)]
fn publish_test_exec_reply(
    fixture: &NativeSignalFixture,
    control: &ThreadControlSlot,
    slot: SlotId,
    receipt_raw: u64,
    root_raw: u64,
) -> carrick_core_abi::ReservationMm {
    publish_test_exec_reply_for(
        fixture,
        fixture.task,
        control,
        slot,
        receipt_raw,
        root_raw,
        false,
    )
}

#[cfg(test)]
fn publish_test_exec_reply_with(
    fixture: &NativeSignalFixture,
    control: &ThreadControlSlot,
    slot: SlotId,
    receipt_raw: u64,
    root_raw: u64,
    corrupt_after_prepare: bool,
) -> carrick_core_abi::ReservationMm {
    publish_test_exec_reply_for(
        fixture,
        fixture.task,
        control,
        slot,
        receipt_raw,
        root_raw,
        corrupt_after_prepare,
    )
}

#[cfg(test)]
fn publish_test_exec_reply_for(
    fixture: &NativeSignalFixture,
    task: &CurrentTask,
    control: &ThreadControlSlot,
    slot: SlotId,
    receipt_raw: u64,
    root_raw: u64,
    corrupt_after_prepare: bool,
) -> carrick_core_abi::ReservationMm {
    use carrick_core_abi::service::{
        ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
        ServiceCell,
    };
    use carrick_guest_arch::{Asid, UserVa};
    use carrick_sched_core::object_wait::ObjectWaitKey;
    use core::num::NonZeroU16;

    let selector = task.service_notice.take().unwrap().unwrap();
    let key = ObjectWaitKey::native_service(selector.record).unwrap();
    let queue = fixture
        .zone
        .object_wait(key, &carrick_sched_core::ShortLockSpin)
        .unwrap();
    let record = fixture.zone.record(selector.record.id);
    let member = record.identity();
    // SAFETY: this test owns the announced exact service member and consumes
    // its ticket once before releasing the queue.
    let ticket =
        unsafe { ServiceCell::claim_notice(&control.service, selector, NonZeroU64::MIN, member) }
            .unwrap();
    let request = ticket.request();
    let manifest_address = ticket.reply_address().unwrap();
    // SAFETY: the ring retains this aligned reply record until acknowledgment.
    let manifest = unsafe { &mut *(manifest_address.raw() as *mut ExecSuccessorManifest) };
    let (successor_mm, root_generation) = manifest.proposal(request.identity).unwrap();
    let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(receipt_raw).unwrap()).unwrap();
    *manifest = manifest
        .seal(
            request.identity,
            receipt,
            ExecSuccessorBacking {
                root: RootGpa::page_aligned(FrameGpa::new(root_raw)).unwrap(),
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
    if corrupt_after_prepare {
        *manifest = ExecSuccessorManifest::propose(request.identity, successor_mm, root_generation);
    }
    assert!(
        ticket
            .publish_exec_prepared(receipt, (), |_, ()| {})
            .is_ok()
    );
    let mut effects = WakeEffects::default();
    queue.notify_object(slot, &mut effects).unwrap();
    drop(queue);
    let mut service = fixture.service();
    service.wake_effects(effects);
    successor_mm
}

#[cfg(test)]
#[test]
fn refused_exec_preparation_is_cancelled_exactly_once() {
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    assert!(take_exec_cancellations().is_empty());
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
            entry.begin_exec_service(test_exec_payload(b"/bin/static")),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let successor_mm = publish_test_exec_reply_with(
        &fixture,
        fixture.control,
        fixture.slot,
        113,
        0xc0_0000,
        true,
    );
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    // SAFETY: the prepared-service wake selected this exact record.
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
    assert!(matches!(
        entry.resume_checkpoint(),
        Ok(NativeResume::Left(None))
    ));
    assert!(entry.take_run_failure().is_none());
    assert_eq!(take_exec_cancellations(), vec![113]);
    assert_eq!(fixture.task.mm.key.load(Ordering::Acquire), 1);
    assert!(fixture.zone.spaces.find(successor_mm.raw()).is_none());
}

struct ExecSibling {
    task: &'static CurrentTask,
    control: &'static ThreadControlSlot,
    slot: SlotId,
    record: RecordRef,
    service_ticket: Option<
        carrick_core_abi::service::ServiceTicket<&'static carrick_core_abi::service::ServiceCell>,
    >,
}

#[cfg(test)]
fn add_exec_sibling(fixture: &NativeSignalFixture, parked_read: bool) -> ExecSibling {
    add_service_sibling(
        fixture,
        parked_read.then_some(carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Syscall,
        }),
    )
}

fn add_service_sibling(
    fixture: &NativeSignalFixture,
    operation: Option<carrick_core_abi::service::ServiceOperation>,
) -> ExecSibling {
    add_signal_sibling(fixture, operation, false)
}

fn add_signal_sibling(
    fixture: &NativeSignalFixture,
    operation: Option<carrick_core_abi::service::ServiceOperation>,
    host_issued: bool,
) -> ExecSibling {
    let binding = ExecutionBinding {
        task: carrick_core_abi::EntryTaskKey::from_raw(42),
        generation: carrick_core_abi::SnapshotGeneration::from_raw(12),
        mm: carrick_core_abi::EntryMmKey::from_raw(1),
        thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(102),
    };
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    if host_issued {
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
    } else {
        let entry = fixture
            .page
            .stock(
                0,
                carrick_el1_abi::EntryIdentity {
                    tid: 42,
                    visible_tid: 42,
                    thread_serial: 102,
                    birth: carrick_core_abi::entry::BirthSerial::of_task(
                        TaskSerial::from_raw_u64(12).unwrap(),
                    ),
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
        assert!(control.publish_visible_tid(42));
        control.publish_host_birth_identity(
            carrick_core::terminal::ThreadBirthIdentity::from_parts(
                binding.task,
                carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(12).unwrap()),
                binding.thread_generation,
            )
            .unwrap(),
        );
        let claim = fixture.page.claim(entry).unwrap();
        fixture
            .page
            .record_born(
                claim,
                carrick_el1_abi::BornRecord {
                    caller_task: 41,
                    caller_serial: 101,
                    clone_flags: 0x0001_0000,
                    clear_child_tid: 0,
                    blocked: carrick_el1_abi::BlockedMask(0),
                },
            )
            .unwrap();
        carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
        fixture.page.publish(entry).unwrap();
    }

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

    let service_ticket = if let Some(operation) = operation {
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot,
        };
        let mut service = fixture.service();
        let mut sibling = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                task,
                fixture.address,
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(
            matches!(
                sibling.begin_service(operation, None),
                Ok(NativeResume::Left(None))
            ),
            "real native service wait must release its execution slot"
        );
        assert!(sibling.take_handoff_receipt().is_some());
        let notice = task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap(),
                &carrick_sched_core::ShortLockSpin,
            )
            .unwrap();
        let ticket = unsafe {
            carrick_core_abi::service::ServiceCell::claim_notice(
                &control.service,
                notice,
                NonZeroU64::MIN,
                fixture.zone.record(record.id).identity(),
            )
        }
        .unwrap();
        drop(queue);
        Some(ticket)
    } else {
        None
    };

    ExecSibling {
        task,
        control,
        slot,
        record,
        service_ticket,
    }
}

#[path = "tests/terminal_park.rs"]
pub mod terminal_park_tests;

#[cfg(test)]
#[test]
fn exit_group_cancels_exception_service_before_publishing_host_wakes() {
    use carrick_core_abi::service::ServiceOperation;
    use carrick_guest_arch::{Access, FaultInfo};
    use carrick_sched_core::object_wait::ResumeDisposition;

    for stop_sibling_slot in [false, true] {
        let fixture = native_exec_fixture();
        let mut sibling = add_service_sibling(
            &fixture,
            Some(ServiceOperation::Fault(FaultInfo {
                address: UserVa::new(0x4000),
                access: Access::Read,
                present: false,
            })),
        );
        // Both fixture CPUs may execute this retained member.
        fixture.zone.record(sibling.record.id).set_affinity(0b11);
        assert_eq!(fixture.page.live(), 2);
        assert_eq!(
            fixture.zone.record(sibling.record.id).resume_disposition(),
            ResumeDisposition::OwnerContinuation(OwnerEntry::Exception)
        );
        assert!(!fixture.zone.record(sibling.record.id).is_native_owned());
        if stop_sibling_slot {
            fixture
                .zone
                .leave_guest(sibling.slot, &carrick_sched_core::ShortLockSpin);
        }
        let page = fixture.page;
        *fixture.runtime.service_cancel_hook.lock() = Some(Box::new(move || {
            assert!(
                page.exit_wait().is_none(),
                "host terminal wakes became visible before native service cancellation"
            );
        }));
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        let mut service = fixture.service();
        {
            let mut root = fixture
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
                root.exit_group(7),
                LifecycleOutcome::Transferred { .. }
            ));
            assert!(root.take_run_failure().is_none());
        }
        assert!(fixture.page.exit_wait().is_some());
        assert!(sibling.control.host_exit_requested());
        sibling
            .service_ticket
            .take()
            .unwrap()
            .complete(true)
            .unwrap_or_else(|_| panic!("cancelled fault ticket must settle"));
        let slot = [fixture.slot, sibling.slot]
            .into_iter()
            .find(|slot| fixture.zone.slot(*slot).queued() != 0)
            .unwrap();
        assert!(
            fixture
                .zone
                .spaces
                .is_open(fixture.zone.record(sibling.record.id).identity().mm),
            "group exit retired the MM before the retained exception checkpoint"
        );
        assert!(
            !fixture.zone.head_needs_host(slot),
            "terminal checkpoint must stay native"
        );
        assert_eq!(
            fixture.zone.switch_in_full(slot).unwrap().record,
            sibling.record.id
        );
        assert!(!fixture.zone.current_affinity_excludes_cpu(slot));
        let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
            .unwrap()
            .words;
        let mut sibling_service = fixture.service();
        {
            let mut member = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource {
                        zone: fixture.zone,
                        slot,
                    },
                    sibling.task,
                    fixture.address,
                    &saved,
                    &mut sibling_service,
                )
                .unwrap();
            assert!(matches!(
                member.resume_checkpoint(),
                Ok(NativeResume::Left(None))
            ));
            assert!(member.take_run_failure().is_none());
        }
        assert!(fixture.zone.live(sibling.record).is_none());
        let slot = [fixture.slot, sibling.slot]
            .into_iter()
            .find(|slot| fixture.zone.slot(*slot).queued() != 0)
            .unwrap();
        assert_eq!(
            fixture.zone.switch_in_full(slot).unwrap().record,
            fixture.record.id
        );
        let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
            .unwrap()
            .words;
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot,
                },
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(root.resume_checkpoint(),
            Ok(NativeResume::Left(Some(status))) if status == LinuxWaitStatus::exited(7)));
        assert!(root.take_run_failure().is_none());
    }
}

#[cfg(test)]
fn test_exec_payload(path: &[u8]) -> Box<[u8]> {
    let mut payload = vec![0; carrick_core_abi::service::EXEC_PAYLOAD_HEADER_BYTES];
    payload.extend_from_slice(path);
    payload.push(0);
    carrick_core_abi::service::encode_exec_payload_header(
        &mut payload,
        carrick_core_abi::service::ExecCall::Execve,
        path.len() + 1,
        0,
        0,
    )
    .unwrap();
    payload.into_boxed_slice()
}

#[cfg(test)]
#[test]
fn native_exec_successor_retracts_exec_cancellation_before_owner_wait() {
    let fixture = native_exec_fixture();
    fixture.control.set_robust_list(0x5000, 24);
    fixture.control.set_clear_child_tid(0x6000);
    fixture
        .control
        .write_altstack(carrick_personality_linux::abi::thread::AltStack {
            sp: 0x7000,
            size: 16 * 1024,
            flags: 0,
        });
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
        let result = entry.begin_exec_service(test_exec_payload(b"/bin/static"));
        match result {
            Ok(NativeResume::Left(None)) => {}
            Ok(_) => panic!("exec intake returned the wrong continuation"),
            Err(error) => panic!("exec intake failed: {error:?}"),
        }
        assert!(entry.take_handoff_receipt().is_some());
    }

    let successor_mm =
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 47, 0x90_0000);

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
    if let Err(reason) = &resumed {
        panic!("exec owner caused run failure after sibling drain: {reason:?}");
    }
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
    assert_eq!(fixture.control.robust_list(), (0, 0));
    assert_eq!(fixture.control.clear_child_tid(), 0);
    assert!(fixture.control.read_altstack().is_disabled());
    assert_eq!(
        fixture
            .runtime
            .graph
            .lock()
            .owner
            .task(entry.key)
            .unwrap()
            .comm_for(41)
            .unwrap(),
        b"static\0\0\0\0\0\0\0\0\0\0"
    );

    assert_eq!(
        fixture.page.process_exit_custody().cancellation(),
        None,
        "the committed successor must not inherit its predecessor's exec cancellation"
    );
    let successor = fixture
        .runtime
        .graph
        .lock()
        .owner
        .task(entry.key)
        .unwrap()
        .native()
        .resources()
        .mm;
    let handle = entry.service.service_mm_handle(&successor).unwrap();
    let successor_entry = fixture
        .zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .unwrap();
    successor_entry
        .admit_notifications(
            handle.incarnation(),
            &carrick_sched_core::BoundedSpin(0),
            &|effects| {
                let _ = effects.deliver_handbacks(&mut |_| {});
            },
        )
        .unwrap();
    let source = successor_entry.notifications(handle.incarnation()).unwrap();
    let observed = source.observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Editor);
    // SAFETY: this exact admitted successor owner and editor revision were
    // sampled immediately before the failed-owner wait is enrolled.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Editor,
            observed.revision(),
        )
    };
    assert!(matches!(
        entry
            .begin_owner_service_wait(
                carrick_core_abi::service::ServiceOperation::CarrierWork {
                    entry: OwnerEntry::Syscall,
                },
                wait,
            )
            .unwrap(),
        NativeResume::Left(None)
    ));
    assert!(entry.take_handoff_receipt().is_some());
}

#[cfg(test)]
#[test]
fn sole_member_exec_closes_admission_before_adopting_successor() {
    let fixture = native_exec_fixture();
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
            entry.begin_exec_service(test_exec_payload(b"/bin/static")),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let host_birth = fixture.page.reserve_host_birth().unwrap();
    let successor_mm =
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 59, 0x98_0000);

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
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
    assert!(matches!(
        entry.resume_checkpoint(),
        Ok(NativeResume::Left(None))
    ));
    assert_eq!(fixture.task.mm.key.load(Ordering::Acquire), 1);
    assert!(fixture.zone.spaces.find(successor_mm.raw()).is_some());
    assert!(fixture.page.exit_wait().is_some());
    assert!(fixture.page.cancel_host_birth_claim(host_birth).is_some());
}

#[cfg(test)]
fn exec_closes_over_predecessor_gate(gate: carrick_el1_abi::GateState) {
    let fixture = native_exec_fixture();
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
            entry.begin_exec_service(test_exec_payload(b"/bin/static")),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    match gate {
        carrick_el1_abi::GateState::ForkClosing => fixture.page.close_for_fork().unwrap(),
        carrick_el1_abi::GateState::HostOnly => fixture.page.decline_to_host(),
        _ => panic!("unsupported predecessor gate"),
    }
    let successor_mm =
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 61, 0x99_0000);

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
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
    assert!(matches!(
        entry.resume_checkpoint(),
        Ok(NativeResume::NoPending)
    ));
    assert!(entry.take_run_failure().is_none());
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        successor_mm.raw()
    );
}

#[cfg(test)]
#[test]
fn native_exec_closes_over_fork_closing_gate() {
    exec_closes_over_predecessor_gate(carrick_el1_abi::GateState::ForkClosing);
}

#[cfg(test)]
#[test]
fn native_exec_closes_over_host_only_gate() {
    exec_closes_over_predecessor_gate(carrick_el1_abi::GateState::HostOnly);
}

#[cfg(test)]
fn exec_after_sibling_drain(parked_read: bool) {
    let fixture = native_exec_fixture();
    let mut sibling = add_exec_sibling(&fixture, parked_read);
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
            entry.begin_exec_service(test_exec_payload(b"/bin/static")),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let successor_mm =
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 71, 0xa0_0000);

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

    if parked_read {
        sibling
            .service_ticket
            .take()
            .unwrap()
            .complete(true)
            .unwrap_or_else(|_| panic!("cancelled native service ticket must settle"));
        // Exec cancellation wakes the real retained service continuation.
        // Its production checkpoint consumes the cancelled operation and
        // publishes the non-owner lifecycle retirement without returning to
        // EL0.
        let sibling_resume_slot = [fixture.slot, sibling.slot]
            .into_iter()
            .find(|slot| fixture.zone.slot(*slot).queued() != 0)
            .unwrap();
        let selected = fixture.zone.switch_in_full(sibling_resume_slot).unwrap();
        assert_eq!(selected.record, sibling.record.id);
        let sibling_source = BornInZoneSource {
            zone: fixture.zone,
            slot: sibling_resume_slot,
        };
        let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
            .unwrap()
            .words;
        let mut sibling_service = fixture.service();
        let mut sibling_entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                sibling_source,
                sibling.task,
                fixture.address,
                &saved,
                &mut sibling_service,
            )
            .unwrap();
        let service_resumed = sibling_entry.resume_service().unwrap();
        if let Err(error) = &service_resumed {
            panic!("cancelled native service failed before lifecycle resume: {error:?}");
        }
        assert!(matches!(service_resumed, Ok(NativeResume::NoPending)));
        let lifecycle_resumed = sibling_entry.resume_pending_lifecycle();
        assert!(
            matches!(
                lifecycle_resumed,
                Some(LifecycleOutcome::Transferred { .. })
            ),
            "cancelled native service returned toward EL0"
        );
        assert!(sibling_entry.take_run_failure().is_none());
    } else {
        // A spinning member observes the host-exit request at its next trap
        // and enters the production lifecycle checkpoint before any EL0
        // instruction can execute again.
        let sibling_source = BornInZoneSource {
            zone: fixture.zone,
            slot: sibling.slot,
        };
        let mut sibling_service = fixture.service();
        let mut sibling_entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                sibling_source,
                sibling.task,
                fixture.address,
                &words(fixture.address),
                &mut sibling_service,
            )
            .unwrap();
        // SAFETY: the execution lane selected this exact record and the
        // host-exit checkpoint publishes the owned continuation before
        // dispatching `resume_pending_lifecycle`.
        unsafe {
            fixture
                .zone
                .record(sibling.record.id)
                .publish_owner_continuation(OwnerEntry::Syscall);
        }
        assert!(matches!(
            sibling_entry.resume_pending_lifecycle(),
            Some(LifecycleOutcome::Transferred { .. })
        ));
        assert!(sibling_entry.take_run_failure().is_none());
    }

    let resume_slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|slot| fixture.zone.slot(*slot).queued() != 0)
        .unwrap();
    let selected = fixture.zone.switch_in_full(resume_slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    let resumed_source = BornInZoneSource {
        zone: fixture.zone,
        slot: resume_slot,
    };
    let resumed_runtime = fixture
        .registry
        .for_entry(resumed_source, fixture.task, fixture.address)
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
            resumed_source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let resumed = entry.resume_checkpoint();
    let resumed_kind = match &resumed {
        Ok(NativeResume::NoPending) => "no-pending",
        Ok(NativeResume::RetrySyscall) => "retry-syscall",
        Ok(NativeResume::Left(_)) => "left",
        Ok(NativeResume::Returned(_)) => "returned",
        Ok(NativeResume::Invalid) => "invalid",
        Err(_) => "run-failure",
    };
    assert!(
        matches!(resumed, Ok(NativeResume::NoPending)),
        "exec owner resumed as {resumed_kind}"
    );
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

#[cfg(test)]
#[test]
fn native_exec_drains_a_spinning_sibling_without_reentering_el0() {
    exec_after_sibling_drain(false);
}

#[cfg(test)]
#[test]
fn native_exec_drains_a_sibling_parked_in_an_owned_read() {
    exec_after_sibling_drain(true);
}

#[cfg(test)]
#[test]
fn concurrent_native_exec_loser_is_killed_without_a_run_failure() {
    let fixture = native_exec_fixture();
    let sibling = add_exec_sibling(&fixture, false);
    assert!(take_exec_cancellations().is_empty());

    let root_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut root_service = fixture.service();
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                root_source,
                fixture.task,
                fixture.address,
                &words(fixture.address),
                &mut root_service,
            )
            .unwrap();
        assert!(matches!(
            root.begin_exec_service(test_exec_payload(b"/bin/winner")),
            Ok(NativeResume::Left(None))
        ));
        assert!(root.take_handoff_receipt().is_some());
    }
    let sibling_source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
    let mut sibling_service = fixture.service();
    {
        let mut loser = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                sibling_source,
                sibling.task,
                fixture.address,
                &words(fixture.address),
                &mut sibling_service,
            )
            .unwrap();
        assert!(matches!(
            loser.begin_exec_service(test_exec_payload(b"/bin/loser")),
            Ok(NativeResume::Left(None))
        ));
        assert!(loser.take_handoff_receipt().is_some());
    }

    let successor_mm =
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 171, 0xd0_0000);
    let _loser_mm = publish_test_exec_reply_for(
        &fixture,
        sibling.task,
        sibling.control,
        sibling.slot,
        172,
        0xe0_0000,
        false,
    );

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                root_source,
                fixture.task,
                fixture.address,
                &saved,
                &mut root_service,
            )
            .unwrap();
        assert!(matches!(
            root.resume_checkpoint(),
            Ok(NativeResume::Left(None))
        ));
        let failure = root.take_run_failure();
        assert!(
            failure.is_none(),
            "losing exec owner failed run: {failure:?}"
        );
    }

    let selected = fixture.zone.switch_in_full(sibling.slot).unwrap();
    assert_eq!(selected.record, sibling.record.id);
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    {
        let mut loser = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                sibling_source,
                sibling.task,
                fixture.address,
                &saved,
                &mut sibling_service,
            )
            .unwrap();
        assert!(matches!(
            loser.resume_service(),
            Some(Ok(NativeResume::NoPending))
        ));
        assert!(matches!(
            loser.resume_pending_lifecycle(),
            Some(LifecycleOutcome::Transferred { .. })
        ));
        assert!(loser.take_run_failure().is_none());
    }
    assert_eq!(take_exec_cancellations(), vec![172]);

    let resume_slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|slot| fixture.zone.slot(*slot).queued() != 0)
        .unwrap();
    let selected = fixture.zone.switch_in_full(resume_slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut root = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: resume_slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut root_service,
        )
        .unwrap();
    assert!(matches!(
        root.resume_checkpoint(),
        Ok(NativeResume::NoPending)
    ));
    assert!(root.take_run_failure().is_none());
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        successor_mm.raw()
    );
}

#[cfg(test)]
fn exec_drain_is_upgraded_by_terminal_sibling(signal: Option<u8>) {
    let fixture = native_exec_fixture();
    let sibling = add_exec_sibling(&fixture, false);
    assert!(take_exec_cancellations().is_empty());
    let root_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut root_service = fixture.service();
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                root_source,
                fixture.task,
                fixture.address,
                &words(fixture.address),
                &mut root_service,
            )
            .unwrap();
        assert!(matches!(
            root.begin_exec_service(test_exec_payload(b"/bin/replaced")),
            Ok(NativeResume::Left(None))
        ));
        assert!(root.take_handoff_receipt().is_some());
    }
    let _successor =
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 181, 0xf0_0000);
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                root_source,
                fixture.task,
                fixture.address,
                &saved,
                &mut root_service,
            )
            .unwrap();
        assert!(matches!(
            root.resume_checkpoint(),
            Ok(NativeResume::Left(None))
        ));
        assert!(root.take_run_failure().is_none());
    }

    let sibling_source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
    let mut sibling_service = fixture.service();
    {
        let mut terminator = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                sibling_source,
                sibling.task,
                fixture.address,
                &words(fixture.address),
                &mut sibling_service,
            )
            .unwrap();
        let outcome = match signal {
            Some(signal) => terminator
                .exit_with_signal(
                    carrick_signal_core::policy::Signal::from_number(signal.into()).unwrap(),
                )
                .unwrap(),
            None => terminator.exit_group(23),
        };
        assert!(matches!(outcome, LifecycleOutcome::Transferred { .. }));
        assert!(terminator.take_run_failure().is_none());
    }
    assert_eq!(take_exec_cancellations(), vec![181]);
    let expected = signal.map_or_else(
        || LinuxWaitStatus::exited(23),
        |signal| LinuxWaitStatus::signaled(signal, false),
    );
    let retained_status = {
        let graph = fixture.runtime.graph.lock();
        graph
            .pending
            .exit(&graph.root_key)
            .and_then(|pending| match pending.operation {
                PendingCloseOperation::Exit { status, .. } => Some(status),
                PendingCloseOperation::Exec(_) => None,
            })
    };
    assert_eq!(
        retained_status,
        Some(expected),
        "terminal close must replace the exec drain and retain its status"
    );

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    {
        let mut root = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                root_source,
                fixture.task,
                fixture.address,
                &saved,
                &mut root_service,
            )
            .unwrap();
        assert!(matches!(
            root.resume_pending_lifecycle(),
            Some(LifecycleOutcome::HostCustody)
        ));
        let failure = root.take_run_failure();
        assert!(
            failure.is_none(),
            "losing exec owner failed run: {failure:?}"
        );
        // Host-born retirement publication below is deliberately the host's
        // half of the production protocol. The ring-owned sibling branches in
        // this suite use `resume_pending_lifecycle` instead.
        fixture
            .page
            .reserve_cancelled_member_exit()
            .unwrap()
            .publish();
        let birth = fixture.control.host_birth_identity().unwrap();
        fixture
            .page
            .publish_exact_host_retirement(fixture.control, birth.retirement());
        root.lifecycle_admission_settled().unwrap();
    }

    let resume_slot = [fixture.slot, sibling.slot]
        .into_iter()
        .find(|slot| fixture.zone.slot(*slot).queued() != 0)
        .unwrap();
    let selected = fixture.zone.switch_in_full(resume_slot).unwrap();
    assert_eq!(selected.record, sibling.record.id);
    let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
        .unwrap()
        .words;
    let mut terminator = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: resume_slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    assert!(matches!(
        terminator.resume_pending_lifecycle(),
        Some(LifecycleOutcome::Transferred { .. })
    ));
    assert!(terminator.take_run_failure().is_none());
}

#[cfg(test)]
#[test]
fn exit_group_wins_over_an_in_progress_native_exec_drain() {
    exec_drain_is_upgraded_by_terminal_sibling(None);
}

#[cfg(test)]
#[test]
fn sigkill_wins_over_an_in_progress_native_exec_drain() {
    exec_drain_is_upgraded_by_terminal_sibling(Some(9));
}

/// Review P0 on #905: ring set*id changes a native caller's credentials
/// without the host. The carrier's exec service checks access with the
/// origin's host credentials, so a caller whose ring credentials changed is
/// refused (counted ENOSYS) before any exec service is issued, never served
/// under the origin's identity. A child inherits its parent's ring
/// credentials at fork, so a root setuid before fork reaches the same check.
#[cfg(test)]
#[test]
fn native_child_exec_after_ring_setuid_is_refused_before_service() {
    use carrick_personality_linux::identity::ProcessIdentityVenue as _;
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let (_, child_address, child_words) = capacity.select().unwrap();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    let mut child = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            child_address,
            &child_words,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        child.resume_checkpoint(),
        Ok(NativeResume::NoPending)
    ));
    assert!(child.caller_has_admitted_credentials().unwrap());
    child.set_uid(1000).unwrap();
    assert!(!child.caller_has_admitted_credentials().unwrap());
    assert!(matches!(
        child.begin_exec_service(test_exec_payload(b"/bin/static")),
        Ok(NativeResume::Returned(result))
            if result.raw() == carrick_syscall_abi::LINUX_ENOSYS.guest_retval()
    ));
    assert!(
        child.take_handoff_receipt().is_none(),
        "no exec service was issued under the wrong credentials"
    );
}

#[cfg(test)]
#[test]
fn native_parent_reaps_then_execs_a_child_after_slot_reuse() {
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let (child_record, child_address, child_words) = capacity.select().unwrap();
    let child_identity = fixture.zone.record(child_record.id).identity();
    // SAFETY: the selected child's exact identity retains this control slot
    // until its process exit settles below.
    let child_control = unsafe { &*(child_identity.control_slot as *const ThreadControlSlot) };
    let child_pid = fixture.task.visible_pid().unwrap();
    assert_ne!(child_pid, 7001);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    {
        let mut child = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                child_address,
                &child_words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            child.resume_checkpoint(),
            Ok(NativeResume::NoPending)
        ));
        assert!(matches!(
            child.begin_exec_service(test_exec_payload(b"/bin/static")),
            Ok(NativeResume::Left(None))
        ));
        assert!(child.take_handoff_receipt().is_some());
    }
    let successor_mm = publish_test_exec_reply(fixture, child_control, fixture.slot, 91, 0xb0_0000);

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, child_record.id);
    // SAFETY: the prepared-service wake selected this exact child record.
    let saved = unsafe { fixture.runtime.record_binding(child_record) }
        .unwrap()
        .words;
    let mut child = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            child_address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        child.resume_checkpoint(),
        Ok(NativeResume::NoPending)
    ));
    assert_eq!(child.calling_tid(), child_pid);
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        successor_mm.raw()
    );
    // This is the successor's first completed syscall boundary. It then exits
    // with status 7, which must wake the already-parked parent wait4 owner.
    assert!(matches!(
        child.exit_group(7),
        LifecycleOutcome::Transferred { .. }
    ));
    drop(child);

    let (parent_record, parent_address, parent_words) = capacity.select().unwrap();
    assert_eq!(fixture.task.visible_pid(), Some(7001));
    let mut parent_service = fixture.service();
    let mut parent = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            parent_address,
            &parent_words,
            &mut parent_service,
        )
        .unwrap();
    match parent.resume_checkpoint() {
        Ok(NativeResume::Returned(result)) => {
            assert_eq!(result.raw(), i64::from(child_pid));
        }
        _ => panic!("parent wait4 did not return the exec child's pid"),
    }
    let second_pid = match parent.fork(ProcessForkChildTid::NONE) {
        LifecycleOutcome::Returned { result, .. } if result.raw() > 0 => result.raw() as u32,
        _ => panic!("parent could not fork after reaping the first exec child"),
    };
    assert!(matches!(
        parent.wait4(
            ProcessWaitPid::from_syscall_argument(u64::MAX),
            UserVa::new(0x1000),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        ),
        LifecycleOutcome::Transferred { .. }
    ));
    assert!(parent.take_handoff_receipt().is_some());
    drop(parent);
    assert_eq!(parent_service.copies, vec![LinuxWaitStatus::exited(7)]);
    assert_ne!(parent_record, child_record);

    let (reused_record, reused_address, reused_words) = capacity.select().unwrap();
    assert_eq!(
        reused_record.id, child_record.id,
        "the retired lifecycle slot must be reused by the second child"
    );
    assert_ne!(
        reused_record.incarnation, child_record.incarnation,
        "slot reuse must publish a fresh record incarnation"
    );
    assert_eq!(fixture.task.visible_pid(), Some(second_pid));
    let mut reused_service = fixture.service();
    let mut reused = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            reused_address,
            &reused_words,
            &mut reused_service,
        )
        .unwrap();
    assert!(matches!(
        reused.resume_checkpoint(),
        Ok(NativeResume::NoPending)
    ));
    assert!(matches!(
        reused.begin_exec_service(test_exec_payload(b"/bin/reused")),
        Ok(NativeResume::Left(None))
    ));
    assert!(reused.take_handoff_receipt().is_some());
}

#[cfg(test)]
#[test]
fn blocking_wait4_reenters_its_owner_after_host_materialization() {
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    assert_eq!(
        fixture.zone.record(fixture.record.id).resume_disposition(),
        carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(OwnerEntry::Syscall),
        "the host materializer must not install a readiness scalar and return to EL0"
    );
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let (_, address, saved) = capacity.select().unwrap();
    let child_pid = fixture.task.visible_pid().unwrap();
    let mut service = fixture.service();
    {
        let mut child = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            child.exit_group(0),
            LifecycleOutcome::Transferred { .. }
        ));
    }
    let (_, address, saved) = capacity.select().unwrap();
    let mut parent = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &saved,
            &mut service,
        )
        .unwrap();
    // The real host materializer re-enters the original syscall instruction.
    // Fresh dispatch must offer its retained owner before invoking wait4 anew.
    assert!(matches!(
        parent.resume_owned_continuation(),
        Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == i64::from(child_pid)
    ));
    assert!(parent.resume_owned_continuation().is_none());
    drop(parent);
    assert_eq!(service.copies, vec![LinuxWaitStatus::exited(0)]);
}

#[cfg(test)]
#[test]
fn sibling_entry_cannot_consume_a_parked_wait4() {
    // The process-keyed wait belongs to the thread that parked it. Another
    // thread of the same process entering the owner must run its own
    // syscall, not complete (or swallow) the parked operation.
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let (_, address, saved) = capacity.select().unwrap();
    let child_pid = fixture.task.visible_pid().unwrap();
    let mut service = fixture.service();
    {
        let mut child = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            child.exit_group(0),
            LifecycleOutcome::Transferred { .. }
        ));
    }
    let (_, address, saved) = capacity.select().unwrap();
    let mut parent = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &saved,
            &mut service,
        )
        .unwrap();
    let waiter = parent.calling_tid();
    // A sibling thread (another tid in the same process) enters the owner.
    parent.set_calling_tid(waiter + 1);
    assert!(!parent.owns_parked_operation());
    assert!(
        parent.resume_pending_wait().is_none(),
        "a sibling's entry must not resume another thread's wait4"
    );
    // The parked thread still owns its operation and reaps exactly once.
    parent.set_calling_tid(waiter);
    assert!(parent.owns_parked_operation());
    assert!(matches!(
        parent.resume_owned_continuation(),
        Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == i64::from(child_pid)
    ));
    assert!(parent.resume_owned_continuation().is_none());
    drop(parent);
    assert_eq!(service.copies, vec![LinuxWaitStatus::exited(0)]);
}

#[cfg(test)]
#[test]
fn carrier_work_wake_redrives_parked_wait4_before_returning_to_user() {
    carrier_work_redrives_parked_wait4(false);
}

#[cfg(test)]
#[test]
fn carrier_work_cancellation_redrives_parked_wait4_before_returning_to_user() {
    carrier_work_redrives_parked_wait4(true);
}

#[cfg(test)]
fn carrier_work_redrives_parked_wait4(cancel: bool) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};

    // The real fork fixture has already parked the parent's blocking wait4.
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let (_, child_address, child_words) = capacity.select().unwrap();
    let child_pid = fixture.task.visible_pid().unwrap();
    let mut child_service = fixture.service();
    {
        let mut child = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                child_address,
                &child_words,
                &mut child_service,
            )
            .unwrap();
        assert!(matches!(
            child.resume_checkpoint(),
            Ok(NativeResume::NoPending)
        ));
        assert!(matches!(
            child.exit_group(0),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(child.take_run_failure().is_none());
    }

    // Carrier work intercepts the selected parent before its wait continuation
    // runs. Its saved x0/readiness word is zero, not a completed wait result.
    let (parent_record, parent_address, parent_words) = capacity.select().unwrap();
    assert_eq!(fixture.task.visible_pid(), Some(7001));
    let parent_identity = fixture.zone.record(parent_record.id).identity();
    // SAFETY: the selected parent retains this exact control through the ACK.
    let parent_control = unsafe { &*(parent_identity.control_slot as *const ThreadControlSlot) };
    let mut parent_service = fixture.service();
    {
        let mut parent = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                parent_address,
                &parent_words,
                &mut parent_service,
            )
            .unwrap();
        assert!(
            fixture
                .runtime
                .graph
                .lock()
                .pending
                .contains_key(&parent.key)
        );
        assert!(matches!(
            parent.begin_service(
                ServiceOperation::CarrierWork {
                    entry: OwnerEntry::Syscall
                },
                None
            ),
            Ok(NativeResume::Left(None))
        ));
        assert!(parent.take_handoff_receipt().is_some());
    }
    assert!(parent_service.copies.is_empty());
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(parent_record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
        )
        .unwrap();
    // SAFETY: the service queue authenticates the retained parent's notice.
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &parent_control.service,
            notice,
            NonZeroU64::MIN,
            parent_identity,
        )
    }
    .unwrap();
    if cancel {
        parent_control
            .service
            .cancel(ticket.request().identity)
            .unwrap();
    }
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);

    let (selected, address, saved) = capacity.select().unwrap();
    assert_eq!(selected, parent_record);
    let mut parent = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &saved,
            &mut parent_service,
        )
        .unwrap();
    assert!(
        matches!(
            parent.resume_service().expect("the selected parent owns its service continuation"),
            Ok(NativeResume::Returned(result)) if result.raw() == i64::from(child_pid)
        ),
        "service readiness must re-drive wait4 and return the child's pid"
    );
    assert!(matches!(
        parent.resume_checkpoint(),
        Ok(NativeResume::NoPending)
    ));
    assert!(matches!(
        parent.wait4(
            ProcessWaitPid::from_syscall_argument(u64::from(child_pid)),
            UserVa::new(0x1000),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        ),
        LifecycleOutcome::Returned { result, .. }
            if result.raw() == carrick_syscall_abi::LINUX_ECHILD.guest_retval()
    ));
    drop(parent);
    assert_eq!(parent_service.copies, vec![LinuxWaitStatus::exited(0)]);
    assert!(capacity.select().is_none());
}

#[cfg(test)]
#[test]
fn native_exec_successor_reaps_its_fork_child() {
    let capacity = NativeServiceCapacityFixture::after_root_exec(1);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };

    let (child_record, child_address, child_words) = capacity.select().unwrap();
    let child_pid = fixture.task.visible_pid().unwrap();
    assert_ne!(child_pid, 7001);
    let mut child_service = fixture.service();
    let mut child = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            child_address,
            &child_words,
            &mut child_service,
        )
        .unwrap();
    assert!(matches!(
        child.resume_checkpoint(),
        Ok(NativeResume::NoPending)
    ));
    assert_eq!(child.calling_tid(), child_pid);
    assert!(matches!(
        child.exit_group(0),
        LifecycleOutcome::Transferred { .. }
    ));
    assert!(child.take_run_failure().is_none());
    drop(child);

    let (parent_record, parent_address, parent_words) = capacity.select().unwrap();
    assert_ne!(parent_record, child_record);
    assert_eq!(fixture.task.visible_pid(), Some(7001));
    let mut parent_service = fixture.service();
    let mut parent = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            parent_address,
            &parent_words,
            &mut parent_service,
        )
        .unwrap();
    assert!(matches!(
        parent.resume_checkpoint(),
        Ok(NativeResume::Returned(result)) if result.raw() == i64::from(child_pid)
    ));
    assert_eq!(parent_service.copies, vec![LinuxWaitStatus::exited(0)]);
}

#[cfg(test)]
#[test]
fn portal_wait_cancellation_resumes_exact_native_service_waiter() {
    use carrick_guest_arch::ProcessContext;
    let fixture = native_exec_fixture();
    let mut service = fixture.service();
    let handle = service.service_mm_handle(&fixture.address).unwrap();
    let space = fixture
        .zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .unwrap();
    space
        .admit_notifications(
            handle.incarnation(),
            &carrick_sched_core::ShortLockSpin,
            &|effects| {
                let _ = effects.deliver_handbacks(&mut |_| {});
            },
        )
        .unwrap();
    let source = space.notifications(handle.incarnation()).unwrap();
    let observed = source.observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Editor);
    // SAFETY: the fixture retains this admitted MM and its observed editor revision.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Editor,
            observed.revision(),
        )
    };
    let enrollment =
        carrick_core_abi::wait::PortalWaitEnrollment::for_owner(fixture.zone, handle, wait)
            .unwrap();
    let birth = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let completed = words(fixture.address).with_syscall_return(0x41);
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                birth,
                fixture.task,
                fixture.address,
                &completed,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry
                .begin_owner_service_wait(
                    carrick_core_abi::service::ServiceOperation::CarrierWork {
                        entry: OwnerEntry::Syscall
                    },
                    wait
                )
                .unwrap(),
            NativeResume::Left(None)
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(matches!(
        fixture.zone.record(fixture.record.id).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    fixture
        .runtime
        .cancel_service(fixture.record, fixture.slot, &mut service)
        .unwrap();
    assert_eq!(
        fixture
            .zone
            .object_queue_census(enrollment.key().index())
            .unwrap()
            .waiters,
        0,
        "service cancellation must detach the enrolled portal waiter"
    );
    assert_eq!(
        fixture.zone.record(fixture.record.id).handback(),
        Some(carrick_sched_core::Handback::Resumed)
    );
    let selected = fixture
        .zone
        .switch_in_full(fixture.slot)
        .expect("cancelled portal waiter must be runnable");
    assert_eq!(selected.record, fixture.record.id);
    assert_eq!(
        selected.result, None,
        "the retained service owns its result"
    );
    // SAFETY: the selected native record is exclusively held by this fixture's driver.
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            birth,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(
        matches!(entry.resume_checkpoint().unwrap(), NativeResume::Returned(result) if result.raw() == 0x41),
        "cancellation resumes the service and preserves its committed result"
    );
}

#[cfg(test)]
#[test]
fn tgkill_reaches_a_futex_parked_host_issued_sibling() {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
    };
    use carrick_signal_core::policy::{SigBlockMask, Signal};
    let fixture = native_exec_fixture();
    fixture.install_handler(10, false);
    let sibling = add_signal_sibling(&fixture, None, true);
    assert_eq!(fixture.page.live(), 2);
    assert!(sibling.control.entry().is_none());
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
    let binding = super::super::common_entry::execution_binding(sibling.task);
    let start = carrick_core::entry::prepare_handoff(binding, source, sibling.record.id).unwrap();
    let word = core::sync::atomic::AtomicU32::new(0);
    let address = word.as_ptr() as u64;
    let guard = fixture
        .zone
        .lock(
            ZoneTables::<ParkedContextWords>::bucket_of_with_context(1, address),
            &carrick_sched_core::BoundedSpin(1000),
        )
        .unwrap();
    let seq = fixture.zone.next_seq(sibling.record.id);
    // Same enrollment/publication boundary used by the futex syscall; no host wait or sleep.
    unsafe {
        *fixture.zone.record(sibling.record.id).ctx_mut() = words(fixture.address);
    }
    fixture
        .zone
        .enqueue(&guard, sibling.record.id, seq, 1, address, u32::MAX, 0)
        .unwrap();
    let _receipt = carrick_core::entry::publish_handoff_park(
        start,
        &guard,
        carrick_core_abi::EntryRecordGeneration(seq),
    )
    .unwrap();
    drop(guard);
    assert_eq!(fixture.zone.record(sibling.record.id).entry_count(), 1);
    assert_eq!(
        fixture.zone.record(sibling.record.id).claim(),
        carrick_sched_core::Claim::Parked { seq }
    );
    let mut service = fixture.service();
    let saved = words(fixture.address);
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
            SignalThreadSelector::from_abi(99),
            SignalThreadSelector::from_abi(42),
            SignalRequest::Probe,
            SignalInfo::Generated(None),
        ),
        Err(carrick_syscall_abi::LINUX_ESRCH),
    );
    assert_eq!(
        sender.tgkill(
            SignalThreadSelector::from_abi(41),
            SignalThreadSelector::from_abi(99),
            SignalRequest::Probe,
            SignalInfo::Generated(None),
        ),
        Err(carrick_syscall_abi::LINUX_ESRCH),
    );
    assert_eq!(
        sender.tgkill(
            SignalThreadSelector::from_abi(41),
            SignalThreadSelector::from_abi(42),
            SignalRequest::Deliver(Signal::from_number(10).unwrap()),
            SignalInfo::Generated(None),
        ),
        Ok(()),
    );
    assert!(sender.take_run_failure().is_none());
    drop(sender);
    assert!(
        fixture
            .runtime
            .current_signals(fixture.task)
            .unwrap()
            .take_deliverable(fixture.record, SigBlockMask::NONE)
            .is_none(),
        "sender cannot steal a sibling's signal"
    );
    let selected = fixture
        .zone
        .switch_in_full(sibling.slot)
        .expect("signal must make the exact futex waiter runnable");
    assert_eq!(selected.record, sibling.record.id);
    assert_eq!(selected.result.map(|value| value as i64), Some(-4));
    assert_eq!(fixture.zone.record(sibling.record.id).entry_count(), 0);
    assert!(
        fixture
            .runtime
            .current_signals(sibling.task)
            .unwrap()
            .take_deliverable(sibling.record, SigBlockMask::NONE)
            .is_some()
    );
}

#[cfg(test)]
fn completed_output_busy_yields(in_preparation: bool) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.child_copy_error = Some(if in_preparation {
        NativeProcessError::Unsupported
    } else {
        NativeProcessError::Busy
    });
    service.prepare_copy_error = in_preparation.then_some(NativeProcessError::Busy);
    let bytes = vec![0x17; 8192];
    take_signal_copies();
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
        let result = entry.finish_copyout(service::OwnedCopyout {
            address: UserVa::new(0x10000),
            bytes: bytes.clone(),
            offset: 0,
            result: SyscallResult::new(37),
        });
        assert!(
            matches!(result, Ok(NativeResume::Left(None))),
            "Busy must retain completed output through CarrierWork: {:?}",
            result.as_ref().err()
        );
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(take_signal_copies().is_empty());
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
        )
        .unwrap();
    // SAFETY: the fixture owns the exact member and its service queue.
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(fixture.record.id).identity(),
        )
    }
    .unwrap();
    assert!(matches!(
        ticket.request().operation,
        ServiceOperation::CarrierWork { .. }
    ));
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);
    service.child_copy_error = None;
    service.prepare_copy_error = None;
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
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
    assert!(
        matches!(entry.resume_checkpoint().unwrap(), NativeResume::Returned(result) if result.raw() == 37)
    );
    assert_eq!(
        take_signal_copies(),
        [
            (UserVa::new(0x10000), bytes[..4096].to_vec()),
            (UserVa::new(0x11000), bytes[4096..].to_vec()),
        ]
    );
}

#[cfg(test)]
#[test]
fn completed_poll_output_copy_busy_yields_then_delivers_the_answer() {
    completed_output_busy_yields(false);
}
#[cfg(test)]
#[test]
fn completed_poll_output_preparation_busy_yields_then_delivers_the_answer() {
    completed_output_busy_yields(true);
}

#[cfg(test)]
fn retained_poll_output_owner_wait(cancel: bool, during_enrollment: bool, production_frame: bool) {
    // Page-aligned guest user input lets the real TrapFrame path read its
    // pollfd array; physical output still goes through this fixture's native
    // service.
    let pages = production_frame.then(|| {
        carrick_test_support::GuestUserBuffer::zeroed(
            1024 * core::mem::size_of::<crate::file_table::PollFd>(),
        )
    });
    let address = pages.as_ref().map_or(0x10000, |pages| pages.arg());
    let expected_result = if production_frame { 1024 } else { 37 };
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    let handle = service.service_mm_handle(&fixture.address).unwrap();
    let space = fixture
        .zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .unwrap();
    space
        .admit_notifications(
            handle.incarnation(),
            &carrick_sched_core::BoundedSpin(0),
            &|effects| {
                let _ = effects.defer_handbacks();
            },
        )
        .unwrap();
    let notifications = space.notifications(handle.incarnation()).unwrap();
    let observed =
        notifications.observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    let output_address = address;
    service.on_copy_complete = Some(Box::new(move |address| {
        if address.raw() == output_address {
            access.raise(space.index());
            if during_enrollment {
                fixture
                    .page
                    .process_exit_custody()
                    .publish_cancellation(carrick_core::terminal::ProcessCancellation::FatalSignal);
            }
        }
    }));
    // SAFETY: this owner retains the live source; the copy hook closes its
    // gate after the first page and before the injected second-page refusal.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    service.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
    service.child_copy_error_at = Some(address + 4096);
    let bytes: Vec<u8> = if production_frame {
        (0..1024)
            .flat_map(|_| {
                [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    carrick_syscall_abi::LINUX_POLLNVAL as u8,
                    0,
                ]
            })
            .collect()
    } else {
        (0..8192).map(|n| (n % 251) as u8).collect()
    };
    take_signal_copies();
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
        if production_frame {
            let mut frame = carrick_el1_abi::TrapFrame::default();
            frame.x[8] = carrick_syscall_abi::nr::PPOLL.raw();
            frame.x[0] = address;
            frame.x[1] = 1024;
            carrick_test_support::assert_guest_args(&frame.x[..6]);
            let counters = carrick_el1_abi::Counters::default();
            let route = crate::dispatch::dispatch_syscall_with_native(
                &mut frame,
                &counters,
                core::slice::from_ref(fixture.task),
                &[],
                &[],
                &[],
                &[],
                &carrick_el1_abi::InotifyNameCache::new(),
                None::<
                    crate::dispatch::Zone<
                        '_,
                        crate::sched::FakeCpu,
                        crate::sched::HardwareUserWord,
                    >,
                >,
                None,
                None,
                Some(&mut *entry),
                Some(source),
                None,
                |_| core::ptr::null_mut(),
            );
            assert_eq!(
                route,
                carrick_personality_linux::dispatch::CompletionRoute::Suspended
            );
            assert_eq!(counters.refused[73].load(Ordering::Relaxed), 0);
        } else {
            assert!(
                matches!(
                    entry.complete_copyout(
                        UserVa::new(address),
                        bytes.clone(),
                        SyscallResult::new(expected_result)
                    ),
                    LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        ..
                    }
                ),
                "completed poll output must retain its result and cursor on an owner wait"
            );
            assert!(entry.take_handoff_receipt().is_some());
        }
    }
    assert_eq!(
        take_signal_copies(),
        [(UserVa::new(address), bytes[..4096].to_vec())]
    );
    if during_enrollment {
        assert!(take_signal_copies().is_empty());
        assert!(
            fixture
                .runtime
                .graph
                .lock()
                .service_wait(&fixture.record)
                .is_none()
        );
        return;
    }

    // A nonfatal service interrupt cannot discard completed readiness or spin
    // through re-enrollment while the gate is still closed.
    fixture
        .runtime
        .cancel_service(fixture.record, fixture.slot, &mut service)
        .unwrap();
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .service_wait(&fixture.record)
            .is_some()
    );
    if cancel {
        fixture
            .page
            .process_exit_custody()
            .publish_cancellation(carrick_core::terminal::ProcessCancellation::FatalSignal);
        fixture
            .runtime
            .cancel_service(fixture.record, fixture.slot, &mut service)
            .unwrap();
    }
    // Make the destination ready even for the fatal case: cancellation must
    // win before any re-preparation, not merely rely on a still-closed gate.
    service.child_copy_error = None;
    access.lower(space.index());
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
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
    let resumed = entry.resume_checkpoint().unwrap();
    if cancel {
        assert!(!matches!(resumed, NativeResume::Returned(_)));
        assert!(
            take_signal_copies().is_empty(),
            "fatal cancellation cannot publish another output chunk"
        );
    } else {
        assert!(
            matches!(resumed, NativeResume::Returned(result) if result.raw() == expected_result)
        );
        assert_eq!(
            take_signal_copies(),
            [(UserVa::new(address + 4096), bytes[4096..].to_vec())]
        );
    }
}

#[cfg(test)]
#[test]
fn completed_ppoll_output_retains_result_and_next_byte_across_owner_wait() {
    retained_poll_output_owner_wait(false, false, false);
}

#[cfg(test)]
#[test]
fn completed_ppoll_output_cancellation_commits_no_more_bytes() {
    retained_poll_output_owner_wait(true, false, false);
}

#[cfg(test)]
#[test]
fn completed_ppoll_output_cancellation_during_enrollment_never_returns_an_errno() {
    retained_poll_output_owner_wait(true, true, false);
}

#[cfg(test)]
#[test]
fn production_trap_frame_ppoll_retains_completed_output_across_owner_wait() {
    retained_poll_output_owner_wait(false, false, true);
}

#[cfg(test)]
#[test]
fn owner_copyout_never_prepares_under_an_ipc_object_lock() {
    use crate::file::UserCopy;
    use carrick_el1::substrate::ipc::{PrefixCopy, StepStatus, transfer};
    use carrick_el1_abi::ipc::{IpcOpKind, IpcOperation, IpcUserVa, pipe::WriteProgress};
    let fixture = native_exec_fixture();
    let shared = std::sync::Arc::new(
        carrick_kernel::el1_ipc::HostIpc::with_limits(
            1 << 20,
            carrick_kernel::el1_ipc::IpcLimits::ZONE,
        )
        .unwrap(),
    );
    let region = shared.region();
    let wait = carrick_sched_core::ShortLockSpin;
    let object = region
        .create_eventfd(7, carrick_el1_abi::ipc::EventMode::Counter, &wait)
        .unwrap();
    let mut service = fixture.service();
    let retained = std::sync::Arc::clone(&shared);
    service.on_copy_complete = Some(Box::new(move |_| {
        assert!(
            retained.region().lock_holder(object).is_none(),
            "owner graph/MM preparation must run after the IPC object unlocks"
        );
    }));
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
            &words(fixture.address),
            &mut service,
        )
        .unwrap();
    struct Refuses;
    impl UserCopy for Refuses {
        fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
            false
        }
        fn copy_out(&mut self, _: u64, _: &[u8]) -> bool {
            false
        }
    }
    let mut user = crate::file::OwnerCopy {
        inner: Refuses,
        owner: Some(&mut *entry),
        wait: None,
    };
    let mut guard = region.lock(object, &wait).unwrap();
    let mut op = IpcOperation {
        kind: IpcOpKind::EventFdRead,
        buf: IpcUserVa(0x10000),
        progress: WriteProgress::new(8),
        ..IpcOperation::EMPTY
    };
    let result = transfer(&mut guard, &mut op, &mut PrefixCopy::new(&mut user)).unwrap();
    assert_eq!(result.0, StepStatus::Fault);
    assert_eq!(
        guard.eventfd().unwrap().value(),
        7,
        "the refused bytes stay at their source"
    );
    let request = user.take_copyout_refusal().unwrap();
    drop(guard);
    let prepared = user.prepare_copyout(
        request,
        carrick_sched_core::object_wait::OperationToken::new(7, 1).unwrap(),
    );
    assert!(matches!(
        prepared,
        carrick_core::mm::transaction::CopyoutPreparation::Ready(_)
    ));
}

/// Inject only the physical preparation error, retaining the production
/// native owner's refusal classification for IPC adapter witnesses.
#[cfg(test)]
pub(crate) fn prepare_copyout_with_error(
    request: carrick_core::mm::transaction::CopyoutRequest,
    operation: carrick_sched_core::object_wait::OperationToken,
    error: NativeProcessError,
) -> carrick_core::mm::transaction::CopyoutPreparation {
    let fixture = native_exec_fixture();
    let mut service = fixture.service();
    service.child_copy_error = Some(error);
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
            &words(fixture.address),
            &mut service,
        )
        .unwrap();
    entry.prepare_owned_copyout(request, operation)
}

#[cfg(test)]
#[test]
fn owner_copyout_unavailable_is_not_a_user_memory_fault() {
    use carrick_personality_linux::lifecycle::OwnedCopyError;
    let fixture = native_exec_fixture();
    for error in [
        NativeProcessError::Busy,
        NativeProcessError::Unsupported,
        NativeProcessError::Stale,
        NativeProcessError::Quarantined,
        NativeProcessError::Fault,
    ] {
        let mut service = fixture.service();
        service.child_copy_error = Some(error);
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
                &words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert_eq!(
            entry.copy_out_owned(UserVa::new(0x10000), &[1]),
            Some(Err(if error == NativeProcessError::Fault {
                OwnedCopyError::Fault
            } else {
                OwnedCopyError::Unavailable
            }))
        );
        if matches!(
            error,
            NativeProcessError::Busy | NativeProcessError::Stale | NativeProcessError::Quarantined
        ) {
            let operation = carrick_sched_core::object_wait::OperationToken::new(7, 1).unwrap();
            let preparation = entry.prepare_owned_copyout(
                carrick_core::mm::transaction::CopyoutRequest {
                    address: UserVa::new(0x10000),
                    len: carrick_guest_arch::GuestLen::new(8),
                },
                operation,
            );
            if error == NativeProcessError::Busy {
                assert!(matches!(
                    preparation,
                    carrick_core::mm::transaction::CopyoutPreparation::Busy(_)
                ));
            } else {
                assert!(matches!(
                    preparation,
                    carrick_core::mm::transaction::CopyoutPreparation::Unrouted(_)
                ));
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum AdapterRefusal {
    None,
    Drain,
    ExitBusy,
    ExitDeferred,
    Transient(NativeProcessError),
    Invariant(NativeProcessError),
    Bridge,
}

#[cfg(test)]
fn retained_ipc_supply(
    supplied: bool,
    already_ready: bool,
    yielding: bool,
    refusal: AdapterRefusal,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_el1_abi::ipc::fd::{AccessMode, Description, Fd, StatusFlags};
    use carrick_el1_abi::ipc::{
        IpcBacking, IpcMmKey, IpcOpKind, IpcOperation, IpcTaskKey, IpcUserVa, OfdPin, WriteProgress,
    };
    let fixture = native_exec_fixture();
    let shared = Box::leak(Box::new(std::sync::Arc::new(
        carrick_kernel::el1_ipc::HostIpc::with_limits(
            1 << 20,
            carrick_kernel::el1_ipc::IpcLimits::ZONE,
        )
        .unwrap(),
    )));
    let object = shared
        .create_eventfd(7, carrick_el1_abi::ipc::EventMode::Counter)
        .unwrap();
    let table = shared.create_table(64, 64).unwrap();
    let description = shared
        .admit_description(Description::new(
            IpcBacking::EventFd { object }.encode(),
            AccessMode::ReadOnly,
            StatusFlags::default(),
        ))
        .unwrap();
    description.install(table, Fd(0), false).unwrap();
    drop(description);
    let region = shared.region();
    let (pin, _) = region
        .fd(carrick_sched_core::ShortLockSpin)
        .pin(table, Fd(0))
        .unwrap();
    let binding = crate::common_entry::execution_binding(fixture.task);
    let op = IpcOperation {
        kind: IpcOpKind::EventFdRead,
        pin: pin.into_raw(),
        object: object.to_raw(),
        task: IpcTaskKey(binding.task.raw()),
        mm: IpcMmKey(binding.mm.raw()),
        buf: IpcUserVa(0x10000),
        progress: WriteProgress::new(8),
        ..IpcOperation::EMPTY
    };
    let token = region.begin_operation(op).unwrap();
    let token = carrick_el1::substrate::ipc::to_sched_token(token).unwrap();
    let identity = token.identity();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.native_ipc = Some(shared.region());
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
        if yielding {
            assert!(matches!(
                entry.yield_owned_operation(token),
                carrick_core::mm::transaction::OwnedOperationYield::Suspended
            ));
        } else {
            entry.suspend_adapter_operation(
                token,
                ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
                    address: UserVa::new(0x10000),
                    access: carrick_guest_arch::Access::Write,
                    present: true,
                }),
                None,
            );
        }

        assert!(
            fixture.task.service_notice.take().unwrap().is_none(),
            "IPC frames must unwind before physical enrollment"
        );
        let work = ServiceOperation::CarrierWork {
            entry: OwnerEntry::Syscall,
        };
        if matches!(
            refusal,
            AdapterRefusal::Bridge | AdapterRefusal::Invariant(_)
        ) {
            let (error, operation) = match refusal {
                AdapterRefusal::Bridge => (NativeProcessError::Busy, NativeServiceExit::Bridge),
                AdapterRefusal::Invariant(error) => (error, NativeServiceExit::CarrierWork),
                _ => unreachable!(),
            };
            assert!(
                matches!(entry.settle_service_exit(Err(error), operation), Err(observed) if observed == error)
            );
            assert_eq!(entry.adapter_ready.as_ref().unwrap().identity, identity);
            assert!(entry.take_handoff_receipt().is_none());
        }
        if !matches!(
            refusal,
            AdapterRefusal::None | AdapterRefusal::Bridge | AdapterRefusal::Invariant(_)
        ) {
            let admission_busy =
                matches!(refusal, AdapterRefusal::Drain | AdapterRefusal::ExitBusy);
            if admission_busy {
                // The real member-wait check refuses admission once. The
                // existing owner settles that wait before the next checkpoint.
                fixture.runtime.graph.lock().insert_member_wait(
                    fixture.record,
                    MemberWait::Signal(PendingSignalWait {
                        kind: PendingSignalKind::Suspend,
                        channel: Arc::new(WaitChannel {
                            generation: ProcessWake::new(),
                            mm: binding.mm.raw(),
                        }),
                        deadline: None,
                    }),
                );
            }
            if matches!(refusal, AdapterRefusal::Drain) {
                entry.drain_owned_preparation();
                assert!(entry.take_handoff_receipt().is_some());
            } else {
                let result = match refusal {
                    AdapterRefusal::ExitBusy => entry.begin_service(work, None),
                    AdapterRefusal::ExitDeferred => Ok(NativeResume::Left(None)),
                    AdapterRefusal::Transient(error) => Err(error),
                    _ => unreachable!(),
                };
                if matches!(refusal, AdapterRefusal::ExitBusy) {
                    assert!(matches!(result, Err(NativeProcessError::Busy)));
                }
                assert!(matches!(
                    entry
                        .settle_service_exit(result, NativeServiceExit::CarrierWork)
                        .unwrap(),
                    NativeResume::Left(None)
                ));
            }
            assert_eq!(entry.adapter_ready.as_ref().unwrap().identity, identity);
            assert!(fixture.task.service_notice.take().unwrap().is_none());
            if admission_busy {
                fixture
                    .runtime
                    .graph
                    .lock()
                    .remove_signal_wait(&fixture.record);
            }
            drop(entry);
            let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
            assert_eq!(selected.record, fixture.record.id);
            let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
                .unwrap()
                .words;
            entry = fixture
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
                entry.resume_checkpoint().unwrap(),
                NativeResume::RetrySyscall
            ));
            let retained = carrick_core::wait::take_object_operation(
                fixture.zone,
                fixture.slot,
                fixture.zone.record(fixture.record.id).identity(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(retained.identity(), identity);
            assert!(matches!(
                entry.yield_owned_operation(retained),
                carrick_core::mm::transaction::OwnedOperationYield::Suspended
            ));
        }
        entry.drain_owned_preparation();
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
        )
        .unwrap();
    // SAFETY: the fixture retains this exact member and authenticates the notice under its service queue.
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(fixture.record.id).identity(),
        )
    }
    .unwrap();
    let request = ticket.request();
    if yielding {
        assert!(matches!(
            request.operation,
            ServiceOperation::CarrierWork { .. }
        ));
    }
    assert!(ticket.complete(supplied).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);
    // Closing the numeric fd cannot revoke the retained operation's pin.
    assert!(
        region
            .fd(carrick_sched_core::ShortLockSpin)
            .close(table, Fd(0))
            .unwrap()
            .is_none()
    );
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
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
    if already_ready {
        assert!(
            matches!(
                entry.park_service(&request, true).unwrap(),
                NativeResume::Left(None)
            ),
            "an acknowledged supply is requeued instead of nested under IPC"
        );
        assert!(entry.take_handoff_receipt().is_some());
        drop(entry);
        let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
        assert_eq!(selected.record, fixture.record.id);
        let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
            .unwrap()
            .words;
        entry = fixture
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
    }
    let resumed = entry.resume_checkpoint().unwrap();
    if supplied {
        assert!(matches!(resumed, NativeResume::RetrySyscall));
        let token = carrick_core::wait::take_object_operation(
            fixture.zone,
            fixture.slot,
            fixture.zone.record(fixture.record.id).identity(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(token.identity(), identity);
        let token = carrick_el1::substrate::ipc::from_sched_token(token).unwrap();
        assert_eq!(region.operation(&token).unwrap(), op);
        // Complete the retained read through the shipping transfer core, not
        // just its preparation. The fd is gone, so only this exact pin can
        // deliver the original counter once and keep the endpoint alive.
        struct CompleteCopy(Vec<u8>);
        impl crate::file::UserCopy for CompleteCopy {
            fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
                false
            }
            fn copy_out(&mut self, address: u64, bytes: &[u8]) -> bool {
                assert_eq!(address, 0x10000);
                self.0.extend_from_slice(bytes);
                true
            }
        }
        let mut active = region.operation(&token).unwrap();
        let mut copy = CompleteCopy(Vec::new());
        let mut object_guard = region
            .lock(object, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        let (status, _) = carrick_el1::substrate::ipc::transfer(
            &mut object_guard,
            &mut active,
            &mut carrick_el1::substrate::ipc::PrefixCopy::new(&mut copy),
        )
        .unwrap();
        assert_eq!(status, carrick_el1::substrate::ipc::StepStatus::Complete);
        assert_eq!(active.progress.written, 8);
        assert_eq!(object_guard.eventfd().unwrap().value(), 0);
        drop(object_guard);
        assert_eq!(copy.0, 7u64.to_ne_bytes());
        let op = region.finish_operation(token).unwrap();
        let release = region
            .fd(carrick_sched_core::ShortLockSpin)
            .unpin_filtered(
                OfdPin::from_raw(op.pin),
                crate::ipc::is_zone_releasable_backing,
            )
            .unwrap();
        crate::ipc::settle_native_release(
            &region,
            release,
            Some((fixture.zone, fixture.slot)),
            fixture.task,
        )
        .unwrap();
    } else {
        assert!(matches!(resumed, NativeResume::Returned(result) if result.raw() == -14));
        assert!(
            !fixture
                .zone
                .record(fixture.record.id)
                .has_object_operation()
        );
    }
    assert!(
        region
            .lock(object, &carrick_sched_core::ShortLockSpin)
            .is_err(),
        "the final description pin was released"
    );
}

#[cfg(test)]
#[test]
fn ipc_backing_supply_retains_the_exact_operation_and_pin() {
    retained_ipc_supply(true, false, false, AdapterRefusal::None);
}
#[cfg(test)]
#[test]
fn ipc_backing_refusal_retires_the_operation_and_pin() {
    retained_ipc_supply(false, false, false, AdapterRefusal::None);
}
#[cfg(test)]
#[test]
fn ipc_already_ready_supply_defers_completion_to_the_checkpoint() {
    retained_ipc_supply(true, true, false, AdapterRefusal::None);
}
#[cfg(test)]
#[test]
fn ipc_already_ready_refusal_retires_at_the_checkpoint() {
    retained_ipc_supply(false, true, false, AdapterRefusal::None);
}

#[cfg(test)]
#[test]
fn ipc_busy_yield_retains_operation_and_pin_through_carrier_work() {
    retained_ipc_supply(true, false, true, AdapterRefusal::None);
}

#[cfg(test)]
#[test]
fn ipc_preparation_busy_once_requeues_then_completes_exact_operation() {
    retained_ipc_supply(true, false, true, AdapterRefusal::Drain);
}

#[cfg(test)]
#[test]
fn native_service_exit_busy_requeues_and_resumes_the_record() {
    retained_ipc_supply(true, false, true, AdapterRefusal::ExitBusy);
}

#[cfg(test)]
#[test]
fn native_service_exit_busy_retains_ipc_operation_and_pin() {
    retained_ipc_supply(
        true,
        false,
        true,
        AdapterRefusal::Transient(NativeProcessError::Busy),
    );
}

#[cfg(test)]
#[test]
fn native_service_exit_deferred_preparation_is_not_quarantined() {
    retained_ipc_supply(true, false, true, AdapterRefusal::ExitDeferred);
}

#[cfg(test)]
#[test]
fn native_service_exit_refusal_policy_preserves_retry_and_authentication() {
    use crate::native_fork_refusal::{NativeForkCause, NativeForkRefusal, NativeForkStage};
    for error in [
        NativeProcessError::Exhausted,
        NativeProcessError::GroupExitCustody,
        NativeProcessError::ForkRefused(NativeForkRefusal {
            stage: NativeForkStage::Commit,
            cause: NativeForkCause::Busy,
        }),
    ] {
        retained_ipc_supply(true, false, true, AdapterRefusal::Transient(error));
    }
    for error in [
        NativeProcessError::Invalid,
        NativeProcessError::Stale,
        NativeProcessError::Quarantined,
    ] {
        retained_ipc_supply(true, false, true, AdapterRefusal::Invariant(error));
    }
}

#[cfg(test)]
#[test]
fn native_service_exit_exec_bridge_keeps_its_existing_refusal() {
    // Native exec's staged bridge has no CarrierWork operation. Even an IPC
    // token cannot authorize retrying its already staged argv (follow-up #1116).
    retained_ipc_supply(true, false, true, AdapterRefusal::Bridge);
}

#[cfg(test)]
#[test]
fn native_service_exit_missing_unowned_receipt_remains_an_invariant() {
    let fixture = native_exec_fixture();
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
            &words(fixture.address),
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.settle_service_exit(Ok(NativeResume::Left(None)), NativeServiceExit::Bridge),
        Err(NativeProcessError::Quarantined)
    ));
    assert!(matches!(
        entry.settle_service_exit(Err(NativeProcessError::Busy), NativeServiceExit::Bridge),
        Err(NativeProcessError::Busy)
    ));
}
