//! Host-only physical service for production native signal path witnesses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use carrick_guest_arch::{ContextGeneration, FrameGpa};
use carrick_sched_core::ParkedContextWords;

#[cfg(test)]
std::thread_local! {
    pub(crate) static FUTEX_MAPPING: core::cell::Cell<Option<Result<bool, NativeProcessError>>> = const { core::cell::Cell::new(None) };
    static TERMINAL_VACATES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_terminal_vacates() -> usize {
    TERMINAL_VACATES.with(|count| count.replace(0))
}

std::thread_local! {
    static SIGNAL_COPIES: std::cell::RefCell<Vec<(UserVa, Vec<u8>)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static SIGNAL_CLOCK_SCRIPT: std::cell::RefCell<std::collections::VecDeque<u64>> = const {
        std::cell::RefCell::new(std::collections::VecDeque::new())
    };
    static SIGNAL_COPY_ERRORS: std::cell::RefCell<std::collections::VecDeque<NativeProcessError>> = const {
        std::cell::RefCell::new(std::collections::VecDeque::new())
    };
    static EXEC_CANCELLATIONS: std::cell::RefCell<Vec<u64>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

// One-shot wait-status copy refusals, consumed before `child_copy_error`.
#[cfg(test)]
std::thread_local! {
    static STATUS_COPY_ERRORS: std::cell::RefCell<std::collections::VecDeque<NativeProcessError>> = const {
        std::cell::RefCell::new(std::collections::VecDeque::new())
    };
}

#[cfg(test)]
type ServicePublishedHook = Option<(usize, Box<dyn FnOnce()>)>;

#[cfg(test)]
std::thread_local! {
    static SERVICE_PUBLISHED_HOOK: std::cell::RefCell<ServicePublishedHook> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_service_published_hook(runtime: usize, hook: Box<dyn FnOnce()>) {
    SERVICE_PUBLISHED_HOOK
        .with(|slot| assert!(slot.borrow_mut().replace((runtime, hook)).is_none()));
}

#[cfg(test)]
pub(super) fn run_service_published_hook(runtime: usize) {
    let hook = SERVICE_PUBLISHED_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(owner, _)| *owner == runtime) {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
std::thread_local! {
    static RETURN_COPYOUTS: std::cell::RefCell<Option<Vec<(UserVa, usize)>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn observe_return_copyouts() {
    RETURN_COPYOUTS.with(|copies| assert!(copies.borrow_mut().replace(Vec::new()).is_none()));
}

#[cfg(test)]
pub(crate) fn record_return_copyout(address: UserVa, len: usize) {
    RETURN_COPYOUTS.with(|copies| {
        if let Some(copies) = copies.borrow_mut().as_mut() {
            copies.push((address, len));
        }
    });
}

#[cfg(test)]
pub(crate) fn take_return_copyouts() -> Vec<(UserVa, usize)> {
    RETURN_COPYOUTS.with(|copies| copies.borrow_mut().take().unwrap())
}

/// The next Physical signal clock reads, in order, before its default
/// 1000-then-2000 clock resumes.
#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn script_signal_clock(reads: &[u64]) {
    SIGNAL_CLOCK_SCRIPT.with(|script| *script.borrow_mut() = reads.iter().copied().collect());
}

/// Fail the next exact-MM user copies (direct or page-admitted owned
/// copies), in order: `Unsupported` is a not-yet-backed page.
#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn fail_signal_copies(errors: &[NativeProcessError]) {
    SIGNAL_COPY_ERRORS.with(|queue| *queue.borrow_mut() = errors.iter().copied().collect());
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
    /// The slot whose entry this service serves, as a production service
    /// carries its own (`Aarch64NativeProcessService::slot`): the waker's
    /// venue for its wake effects. A test that runs an entry on another
    /// slot sets it first.
    pub waker_slot: SlotId,
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
    fn vacate_terminal_space(
        &mut self,
        source: carrick_el1_abi::BornInZoneSource<'a, C>,
    ) -> Result<(), NativeProcessError> {
        let _ = source;
        #[cfg(test)]
        TERMINAL_VACATES.with(|count| count.set(count.get() + 1));
        Ok(())
    }

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
        // Production forks publish MM notification sources. Retire that exact
        // source through its release venue before recycling the predecessor;
        // source-free fixtures follow the same terminal entry transition.
        self.zone
            .space_entry(predecessor.mm.raw())
            .ok_or(NativeProcessError::Stale)?
            .retire_entry(
                crate::sched::object_wait::space_access(self.zone, slot)
                    .venue()
                    .ok_or(NativeProcessError::Stale)?,
            );
        self.zone.spaces.open(new);
        self.zone
            .install_space(slot, successor.mm.raw().get())
            .ok_or(NativeProcessError::Stale)?;
        Ok(())
    }
    fn exec_ipc_binding(
        &self,
    ) -> Option<(
        carrick_el1_abi::ipc::IpcRegion<'_>,
        &carrick_el1_abi::ipc_tables::IpcTableMap,
    )> {
        static MAP: std::sync::OnceLock<&'static carrick_el1_abi::ipc_tables::IpcTableMap> =
            std::sync::OnceLock::new();
        let map = carrick_el1_abi::ipc_table_map_host().unwrap_or_else(|| {
            MAP.get_or_init(|| {
                let layout = std::alloc::Layout::new::<carrick_el1_abi::ipc_tables::IpcTableMap>();
                // SAFETY: typed aligned zeroed allocation is a valid empty IpcTableMap
                // retained for the life of the isolated test process.
                unsafe {
                    let ptr = std::alloc::alloc_zeroed(layout)
                        .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>();
                    assert!(!ptr.is_null());
                    Box::leak(Box::from_raw(ptr))
                }
            })
        });
        Some((self.native_ipc?, map))
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
    fn native_service_doorbell(&mut self) -> bool {
        #[cfg(test)]
        {
            ENTROPY_DOORBELL.with(|hook| {
                if let Some(hook) = hook.borrow_mut().as_mut() {
                    hook();
                    true
                } else {
                    false
                }
            })
        }
        #[cfg(not(test))]
        {
            false
        }
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

    /// The test carrier's host-served root sits in `/`.
    fn root_fork_seed(
        &mut self,
        _capability: carrick_core_abi::service::ExecCapabilityId,
    ) -> Result<super::RootFsSeed, NativeProcessError> {
        Ok(super::RootFsSeed::Seeded(
            carrick_personality_linux::task_fs::TaskFs::default(),
        ))
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
        address: UserVa,
        status: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError> {
        #[cfg(test)]
        if let Some(error) = STATUS_COPY_ERRORS.with(|errors| errors.borrow_mut().pop_front()) {
            return Err(error);
        }
        if let Some(error) = self.child_copy_error {
            return Err(error);
        }
        if self.refuse_copy {
            return Err(NativeProcessError::Fault);
        };
        self.copies.push(status);
        if let Some(hook) = &mut self.on_copy_complete {
            hook(address);
        }
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
        if let Some(error) = SIGNAL_COPY_ERRORS.with(|errors| errors.borrow_mut().pop_front()) {
            return Err(error);
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
    fn copy_syscall_output(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        self.copy_owned_bytes(mm, address, bytes)
    }
    fn copy_owned_bytes(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        // Match the physical CPL0 service: one owner admission per page.
        let mut offset = 0;
        while offset < bytes.len() {
            let address = address.raw() + offset as u64;
            let count = (4096 - (address as usize & 4095)).min(bytes.len() - offset);
            self.copy_signal_bytes(mm, UserVa::new(address), &bytes[offset..offset + count])?;
            offset += count;
        }
        Ok(())
    }
    #[cfg(test)]
    fn futex_shared_private(
        &mut self,
        _: &Self::Mm,
        _: UserVa,
    ) -> Result<bool, NativeProcessError> {
        FUTEX_MAPPING.with(|slot| slot.get().unwrap_or(Ok(false)))
    }
    fn prepare_owned_read(
        &mut self,
        _: &Self::Mm,
        request: carrick_core::user_copy::GuestCopyRequest,
    ) -> Result<(), NativeProcessError> {
        assert_eq!(request.access, carrick_guest_arch::Access::Read);
        self.prepare_copy_error.map_or(Ok(()), Err)
    }
    #[cfg(test)]
    fn copyout_fault(
        &self,
        address: UserVa,
    ) -> Option<(carrick_guest_arch::FaultInfo, NonZeroU64)> {
        matches!(self.child_copy_error, Some(NativeProcessError::Unsupported)).then_some((
            carrick_guest_arch::FaultInfo {
                address,
                access: carrick_guest_arch::Access::Write,
                present: false,
            },
            NonZeroU64::MIN,
        ))
    }
    #[cfg(test)]
    fn apply_fault_reply(
        &mut self,
        slot: &carrick_el1_abi::PortalGrantSlot,
        disposition: super::FaultReplyDisposition,
    ) -> Result<(), carrick_core::mm::transaction::MmError> {
        FAULT_REPLY_CALLS.with(|calls| calls.set(calls.get() + 1));
        FAULT_REPLY_LAST_CANCEL
            .with(|cancel| cancel.set(disposition == super::FaultReplyDisposition::Cancel));
        if let Some(wait) = FAULT_REPLY_WAIT_ONCE.with(|once| once.take()) {
            return Err(carrick_core::mm::transaction::MmError::Wait(wait));
        }
        if disposition == super::FaultReplyDisposition::Cancel && slot.window().is_none() {
            Ok(())
        } else {
            Err(carrick_core::mm::transaction::MmError::Core)
        }
    }
    fn prepare_owned_write(
        &mut self,
        _: &Self::Mm,
        request: carrick_core::mm::transaction::CopyoutRequest,
    ) -> Result<(), NativeProcessError> {
        #[cfg(test)]
        ENTROPY_PREPARES.with(|count| count.set(count.get() + 1));
        #[cfg(test)]
        if ENTROPY_PREPARE_BUSY_ONCE.with(|busy| busy.replace(false)) {
            return Err(NativeProcessError::Busy);
        }
        #[cfg(test)]
        if ENTROPY_WRITABLE_END.with(|limit| {
            limit.get().is_some_and(|limit| {
                request
                    .address
                    .raw()
                    .checked_add(request.len.raw())
                    .is_none_or(|end| end > limit.raw())
            })
        }) {
            return Err(NativeProcessError::Fault);
        }
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
    fn signal_deadline(
        &mut self,
        nanos: u64,
    ) -> Result<carrick_guest_arch::Deadline, NativeProcessError> {
        Ok(carrick_guest_arch::Deadline(
            carrick_guest_arch::CounterTick::new(1000 + nanos),
        ))
    }
    /// One tick per nanosecond, matching `signal_deadline` above.
    fn signal_frequency(
        &mut self,
    ) -> Result<carrick_guest_arch::CounterFrequency, NativeProcessError> {
        Ok(carrick_guest_arch::CounterFrequency::new(
            NonZeroU64::new(1_000_000_000).ok_or(NativeProcessError::Invalid)?,
        ))
    }
    fn arm_signal_timer(
        &mut self,
        _: carrick_guest_arch::Deadline,
    ) -> Result<(), NativeProcessError> {
        Ok(())
    }
    fn counter_frequency(
        &self,
    ) -> Result<carrick_personality_linux::sched::FutexFrequency, NativeProcessError> {
        Ok(carrick_personality_linux::sched::FutexFrequency::from_hz(
            1000,
        ))
    }
    fn signal_now(&mut self) -> Result<carrick_guest_arch::CounterTick, NativeProcessError> {
        if let Some(mut hook) = self.on_signal_clock.take() {
            hook();
        }
        if let Some(now) = SIGNAL_CLOCK_SCRIPT.with(|script| script.borrow_mut().pop_front()) {
            return Ok(carrick_guest_arch::CounterTick::new(now));
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
        crate::sched::object_wait::deliver_wake_effects(self.zone, self.waker_slot, effects);
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
pub struct NativeSignalFixture<C: ProcessContext + 'static = ParkedContextWords> {
    zone: &'static ZoneTables<C>,
    registry: &'static NativeProcessRegistry<'static, AddressContext<RootGpa>, C>,
    runtime: Arc<NativeProcessRuntime<'static, AddressContext<RootGpa>, C>>,
    task: &'static CurrentTask,
    control: &'static ThreadControlSlot,
    page: &'static ThreadLifecyclePage,
    child_page: &'static ThreadLifecyclePage,
    child_controls: &'static [ThreadControlSlot; 9],
    address: AddressContext<RootGpa>,
    slot: SlotId,
    record: RecordRef,
    handler_signum: core::sync::atomic::AtomicI32,
    make_words: fn(AddressContext<RootGpa>) -> C,
}

impl<C: ProcessContext + 'static> Drop for NativeSignalFixture<C> {
    fn drop(&mut self) {
        // The registry's member and group rows retain the signal owner even
        // after the fixture's runtime handle is dropped.
        let process = self.runtime.graph.lock().root_key;
        self.registry.unregister_process(&self.runtime, process);
    }
}

impl<C: ProcessContext + 'static> NativeSignalFixture<C> {
    fn new_with_context<B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
        binding: ExecutionBinding,
        process: carrick_core_abi::EntryTaskKey,
        process_birth: carrick_core_abi::BirthSerial,
        make_words: fn(AddressContext<RootGpa>) -> C,
    ) -> Self {
        let fixture = Self::with_identity_for::<B>(
            true,
            |_| (binding, process, process_birth, 5),
            make_words,
        );
        fixture.runtime.give_fixture_root_a_cwd();
        fixture
    }

    fn with_identity_for<B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
        seed: bool,
        identity: impl FnOnce(
            &'static ZoneTables<C>,
        ) -> (
            ExecutionBinding,
            carrick_core_abi::EntryTaskKey,
            carrick_core_abi::BirthSerial,
            u64,
        ),
        make_words: fn(AddressContext<RootGpa>) -> C,
    ) -> Self {
        let layout = std::alloc::Layout::new::<ZoneTables<C>>();
        // SAFETY: one aligned allocation owns this zero-valid compact zone for
        // the entire leaked host-test fixture lifetime.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<C>>();
            assert!(!ptr.is_null());
            Box::leak(Box::from_raw(ptr))
        };
        let (binding, process, process_birth, file_table) = identity(zone);
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
            file_table,
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
                file_table,
                generation: binding.generation.raw(),
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();
        let source = BornInZoneSource { zone, slot };
        if seed {
            seed_fixture_namespace(zone, task, page);
        }
        let runtime = Arc::new(
            NativeProcessRuntime::admit_fresh_root::<B>(
                source,
                task,
                page,
                control,
                address,
                address,
                make_words(address),
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
            make_words,
        }
    }

    pub fn record(&self) -> RecordRef {
        self.record
    }

    pub fn control_slot(&self) -> &ThreadControlSlot {
        self.control
    }

    fn service(&self) -> Physical<'static, C> {
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
            waker_slot: carrick_sched_core::SlotId::new(0),
            on_signal_clock: None,
        }
    }
}

impl NativeSignalFixture {
    pub fn new(
        binding: ExecutionBinding,
        process: carrick_core_abi::EntryTaskKey,
        process_birth: carrick_core_abi::BirthSerial,
    ) -> Self {
        let fixture = Self::admit_host_root(binding, process, process_birth);
        fixture.runtime.give_fixture_root_a_cwd();
        fixture
    }

    fn admit_host_root(
        binding: ExecutionBinding,
        process: carrick_core_abi::EntryTaskKey,
        process_birth: carrick_core_abi::BirthSerial,
    ) -> Self {
        Self::with_identity(true, |_| (binding, process, process_birth, 5))
    }

    /// Admit the identities established by production bootstrap without seeding
    /// a fixture namespace domain or issuing any fixture identity claims.
    pub fn from_bootstrap(
        identity: impl FnOnce(
            &'static ZoneTables<ParkedContextWords>,
        ) -> (
            ExecutionBinding,
            carrick_core_abi::EntryTaskKey,
            carrick_core_abi::BirthSerial,
        ),
    ) -> Self {
        Self::with_identity(false, |zone| {
            let (binding, process, birth) = identity(zone);
            (binding, process, birth, 5)
        })
    }

    /// [`Self::from_bootstrap`] that also names the root's published
    /// descriptor table, as the carrier publishes it for the root's current
    /// image (an exec replaces it).
    pub fn from_bootstrap_with_file_table(
        identity: impl FnOnce(
            &'static ZoneTables<ParkedContextWords>,
        ) -> (
            ExecutionBinding,
            carrick_core_abi::EntryTaskKey,
            carrick_core_abi::BirthSerial,
            u64,
        ),
    ) -> Self {
        Self::with_identity(false, identity)
    }

    /// The exec capability every exec and root fork seed of this admitted
    /// tree names.
    pub fn exec_capability(&self) -> Option<carrick_core_abi::service::ExecCapabilityId> {
        self.runtime.exec_capability()
    }

    fn with_identity(
        seed: bool,
        identity: impl FnOnce(
            &'static ZoneTables<ParkedContextWords>,
        ) -> (
            ExecutionBinding,
            carrick_core_abi::EntryTaskKey,
            carrick_core_abi::BirthSerial,
            u64,
        ),
    ) -> Self {
        Self::with_identity_for::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(seed, identity, words)
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
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> carrick_core::user_copy::CopyOutcome,
    ) -> Result<carrick_personality_linux::signal::SignalFrameSetup, Self::Error> {
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
        seed_fixture_namespace(zone, root, page);
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
        runtime.give_fixture_root_a_cwd();
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
            waker_slot: carrick_sched_core::SlotId::new(0),
            on_signal_clock: None,
        }
    }
    /// Complete a production zone readiness decision, refuse its second output
    /// piece on the exact MM gate, drain the source, then deliver the retained
    /// answer. Only the physical memory service is substituted.
    #[cfg(test)]
    pub fn poll_output_owner_wait(&self) {
        use crate::file_table::{LINUX_POLLIN, PollFd};
        use carrick_el1_abi::ipc::{EventMode, IpcBacking, fd};
        use carrick_kernel::el1_ipc::{HostIpc, HostTable};
        use carrick_kernel::el1_zone::HostLockWait;
        use carrick_test_support::GuestUserBuffer;
        let host: &'static Arc<HostIpc> =
            Box::leak(Box::new(Arc::new(HostIpc::new(1 << 20).unwrap())));
        let table = HostTable::create(host.clone(), 64, 8).unwrap();
        let object = host
            .region()
            .create_eventfd(1, EventMode::Counter, &HostLockWait)
            .unwrap();
        let description = host
            .admit_description(fd::Description::new(
                IpcBacking::EventFd { object }.encode(),
                fd::AccessMode::ReadWrite,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        description.install(table.id(), fd::Fd(0), false).unwrap();
        let map = Box::leak(Box::new(unsafe {
            core::mem::zeroed::<carrick_el1_abi::ipc_tables::IpcTableMap>()
        }));
        map.publish(5, table.id().to_raw()).unwrap();
        let tables = Box::leak(Box::new(crate::ipc::MapTables(map)));
        let venue = crate::ipc::IpcVenue {
            region: host.region(),
            tables,
        };
        let pages = GuestUserBuffer::zeroed(8192);
        // Place the two-byte revents across a page boundary.
        let address = pages.arg() + 4089;
        let pollfd = PollFd {
            fd: 0,
            events: LINUX_POLLIN,
            revents: 0x7777,
        };
        // SAFETY: this guest allocation covers the exact eight-byte record.
        unsafe {
            (address as *mut PollFd).write_unaligned(pollfd);
        }
        let mut physical = self.physical();
        let handle = physical.service_mm_handle(&self.address).unwrap();
        let space = self
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
        let observed = space
            .notifications(handle.incarnation())
            .unwrap()
            .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
        let slot = SlotId::new(0);
        let access = crate::sched::object_wait::space_access(self.zone, slot);
        physical.on_copy_complete = Some(Box::new(move |at| {
            if at.raw() == address + 6 {
                access.raise(space.index());
            }
        }));
        // SAFETY: this fixture owns the exact-MM gate until output completes.
        let wait = unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                handle,
                carrick_core_abi::PortalWaitCause::Gate,
                observed.revision(),
            )
        };
        physical.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
        physical.child_copy_error_at = Some(address + 7);
        take_signal_copies();
        let source = BornInZoneSource {
            zone: self.zone,
            slot,
        };
        {
            let mut entry = self
                .runtime
                .enter_registered(
                    self.registry,
                    source,
                    self.root,
                    self.address,
                    &self.words,
                    &mut physical,
                )
                .unwrap();
            let mut frame = carrick_el1_abi::TrapFrame {
                elr: 0x4004,
                ..Default::default()
            };
            frame.x[8] = 73;
            frame.x[0] = address;
            frame.x[1] = 1;
            let mut cpu = crate::sched::FakeCpu::default();
            let route = crate::dispatch::dispatch_syscall_with_native(
                &mut frame,
                &carrick_el1_abi::Counters::new(),
                core::slice::from_ref(self.root),
                &[],
                &[],
                &[],
                &[],
                &carrick_el1_abi::InotifyNameCache::new(),
                Some(crate::dispatch::Zone {
                    tables: self.zone,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                }),
                Some(&venue),
                None,
                Some(&mut *entry),
                Some(source),
                None,
                |_| core::ptr::null_mut(),
            );
            assert_eq!(
                route,
                carrick_personality_linux::dispatch::CompletionRoute::Suspended,
                "completed zone readiness must enter exact-MM preparation, result={}",
                frame.x[0] as i64
            );
        }
        assert_eq!(
            take_signal_copies(),
            [(
                UserVa::new(address + 6),
                vec![LINUX_POLLIN.to_ne_bytes()[0]]
            )]
        );
        let record = self.root_control.zone_record().unwrap();
        // Change readiness after completion. Output must not be re-polled.
        let drained = host
            .region()
            .lock(object, &HostLockWait)
            .unwrap()
            .eventfd()
            .unwrap()
            .try_read()
            .result;
        assert_eq!(drained, Ok(1));
        self.runtime
            .cancel_service(record, slot, &mut physical)
            .unwrap();
        physical.child_copy_error = None;
        // The fake executor returns its vCPU before the release, so the real
        // queue may place this exact parked record instead of a host handback.
        self.zone.drive(slot, 1);
        self.zone.enter_guest(slot);
        access.lower(space.index());
        assert_eq!(self.zone.switch_in_full(slot).unwrap().record, record.id);
        let saved = unsafe { self.runtime.record_binding(record) }
            .unwrap()
            .words;
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                source,
                self.root,
                self.address,
                &saved,
                &mut physical,
            )
            .unwrap();
        assert!(
            matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(result) if result.raw() == 1)
        );
        drop(entry);
        assert_eq!(
            take_signal_copies(),
            [(
                UserVa::new(address + 7),
                vec![LINUX_POLLIN.to_ne_bytes()[1]]
            )]
        );
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
        Self::new_with_rusage(children, UserVa::new(0))
    }

    fn new_with_rusage(children: usize, rusage: UserVa) -> Self {
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
        Self::from_fixture_rusage(fixture, children, rusage)
    }

    #[cfg(test)]
    fn from_fixture(fixture: NativeSignalFixture, children: usize) -> Self {
        Self::from_fixture_rusage(fixture, children, UserVa::new(0))
    }

    fn from_fixture_rusage(fixture: NativeSignalFixture, children: usize, rusage: UserVa) -> Self {
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
                rusage,
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
                root.begin_exec_service(
                    test_exec_payload(b"/bin/static"),
                    None,
                    NativeServiceCall::new(
                        carrick_guest_arch::NativeOrdinal::new(221),
                        &carrick_el1_abi::Counters::new()
                    )
                ),
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
            root.resume_checkpoint(|_| Ok(None)),
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
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        assert!(matches!(
            entry
                .begin_service(
                    ServiceOperation::CarrierWork {
                        entry: carrick_sched_core::object_wait::OwnerEntry::Syscall,
                        demand: carrick_core_abi::service::CarrierDemand::Work,
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
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
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
                    &|owned| {
                        crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                    },
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
                entry.resume_checkpoint(|_| Ok(None)).unwrap(),
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
    native_exec_fixture_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(words)
}

fn native_exec_fixture_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) -> NativeSignalFixture<C> {
    NativeSignalFixture::new_with_context::<B>(
        ExecutionBinding {
            task: carrick_core_abi::EntryTaskKey::from_raw(41),
            generation: carrick_core_abi::SnapshotGeneration::from_raw(11),
            mm: carrick_core_abi::EntryMmKey::from_raw(1),
            thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(101),
        },
        carrick_core_abi::EntryTaskKey::from_raw(41),
        carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(11).unwrap()),
        make_words,
    )
}

#[test]
#[cfg(test)]
fn native_clock_requires_retained_payload_before_service_publication() {
    use carrick_core_abi::clock::{CLOCK_RECORD_BYTES, ClockCapabilityId};
    use carrick_core_abi::service::{ClockPayloadDescriptor, ServiceOperation};

    let fixture = native_exec_fixture();
    let mut service = fixture.service();
    let context = words(fixture.address);
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
            &context,
            &mut service,
        )
        .unwrap();
    let operation = ServiceOperation::Clock {
        capability: ClockCapabilityId::new(NonZeroU64::MIN),
        payload: ClockPayloadDescriptor::checked(
            carrick_guest_arch::GuestVa::new(0x1000),
            carrick_guest_arch::GuestLen::new(CLOCK_RECORD_BYTES as u64),
            carrick_guest_arch::NativeOrdinal::new(113),
        )
        .unwrap(),
    };
    assert!(matches!(
        entry.begin_service(operation, None),
        Err(NativeProcessError::Stale)
    ));
    assert_eq!(fixture.task.service_notice.take().unwrap(), None);
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
    assert!(
        !fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&fixture.record)
    );
}

#[cfg(test)]
#[test]
fn native_clock_sample_retains_reply_across_copyout_busy() {
    use carrick_core_abi::clock::{CLOCK_RECORD_BYTES, ClockCapabilityId};
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_kernel::clock_service::ClockResourceService;
    use carrick_kernel::kernel::container::ClockDomain;
    use std::time::{Duration, UNIX_EPOCH};

    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.child_copy_error = Some(NativeProcessError::Busy);
    let clock = Arc::new(ClockDomain::deterministic(
        UNIX_EPOCH + Duration::from_secs(1234),
    ));
    let resource = ClockResourceService::new(clock.clone());
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
        assert!(matches!(
            entry
                .begin_clock_sample(
                    ClockCapabilityId::new(NonZeroU64::MIN),
                    carrick_abi::LINUX_CLOCK_REALTIME,
                    UserVa::new(0x10000),
                    carrick_guest_arch::NativeOrdinal::new(113),
                )
                .unwrap(),
            NativeResume::Left(None)
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    // Complete the resource request, then the copyout's physical-owner work.
    // The second request must never sample the clock again.
    for round in 0..2 {
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record)
                    .unwrap(),
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        // SAFETY: the fixture retains the exact member under its service queue.
        let ticket = unsafe {
            ServiceCell::claim_notice(
                &fixture.control.service,
                notice,
                NonZeroU64::MIN,
                fixture.zone.record(fixture.record.id).identity(),
            )
        }
        .unwrap();
        if round == 0 {
            let ServiceOperation::Clock { payload, .. } = ticket.request().operation else {
                panic!("sample must use a typed clock request");
            };
            assert_eq!(payload.length().raw(), CLOCK_RECORD_BYTES as u64);
            // SAFETY: this ticket owns the ring's retained request allocation
            // through ACK; the fixture models the carrier's mapped supervisor storage.
            let record =
                unsafe { &mut *(payload.address().raw() as *mut [u8; CLOCK_RECORD_BYTES]) };
            resource.serve_record(record).unwrap();
        } else {
            assert!(matches!(
                ticket.request().operation,
                ServiceOperation::CarrierWork { .. }
            ));
            service.child_copy_error = None;
        }
        assert!(ticket.complete(true).is_ok());
        queue
            .notify_object(fixture.slot, &mut WakeEffects::default())
            .unwrap();
        drop(queue);
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
        let result = entry.resume_checkpoint(|_| Ok(None)).unwrap();
        if round == 0 {
            assert!(matches!(result, NativeResume::Left(None)));
            // resume_checkpoint consumes the exact handoff receipt itself.
            assert!(entry.take_handoff_receipt().is_none());
            assert!(take_signal_copies().is_empty());
            clock.advance(Duration::from_secs(10)).unwrap();
        } else {
            assert!(matches!(result, NativeResume::Returned(result) if result.raw() == 0));
        }
    }
    let mut expected = 1234u64.to_le_bytes().to_vec();
    expected.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(take_signal_copies(), [(UserVa::new(0x10000), expected)]);
    assert!(
        !fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&fixture.record)
    );
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
}

#[cfg(test)]
fn arm_words(address: AddressContext<RootGpa>) -> carrick_el1_abi::Aarch64ParkedContext {
    let mut native = carrick_el1_abi::ThreadCtx::ZERO;
    native.pc = 0x40_0004;
    native.sp_el0 = 0x80_0000;
    carrick_el1_abi::Aarch64ParkedContext::from_parts(native, address)
}

/// These are corrupt custody, not a sibling holding a releasable resource.
/// Drive the same begin/settle pair as arm_native_service_exit: an exact
/// member may have only one cell, pending row and execution-lane notice.
#[test]
#[cfg(test)]
fn native_service_duplicate_custody_is_an_invariant_at_bridge_settlement() {
    use carrick_core_abi::service::{ServiceOperation, ServiceOrigin};
    for occupied_notice in [false, true] {
        let fixture = native_exec_fixture();
        let mut service = fixture.service();
        let context = words(fixture.address);
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
                &context,
                &mut service,
            )
            .unwrap();
        let mm = entry.service.service_mm_handle(&fixture.address).unwrap();
        service::bind_member_service(
            fixture.zone,
            entry.key,
            ServiceOrigin::Initial,
            fixture.record,
            entry.binding.thread_generation,
            fixture.control,
            mm,
        )
        .unwrap();
        let birth = fixture
            .control
            .service
            .bound_birth(entry.key, entry.binding.thread_generation, fixture.record)
            .unwrap();
        let operation = ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(115),
        };
        let request = fixture
            .control
            .service
            .publish(birth, entry.binding.generation, operation, None)
            .unwrap();
        if occupied_notice {
            // Keep the lane's earlier notice, but restore the cell to idle.
            fixture
                .task
                .service_notice
                .publish(request.identity.into())
                .unwrap();
            // SAFETY: this fixture never runs a transport. The retained notice
            // is deliberately corrupt lane custody, not a delivered ticket.
            unsafe { fixture.control.service.abort_unpublished(request.identity) }.unwrap();
            fixture.control.service.consume(request.identity).unwrap();
        }
        let result = entry.begin_service(operation, None);
        assert!(
            matches!(
                entry.settle_service_exit(result, NativeServiceExit::Bridge),
                Err(NativeProcessError::Quarantined)
            ),
            "duplicate custody must not report transient Busy (notice={occupied_notice})"
        );
        assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
        assert!(
            !fixture
                .runtime
                .graph
                .lock()
                .has_member_wait(&fixture.record)
        );
        assert_eq!(
            fixture.task.service_notice.take().unwrap(),
            occupied_notice.then_some(request.identity.into()),
            "refused publication must preserve the earlier notice"
        );
    }
}

#[test]
#[cfg(test)]
fn native_service_suspended_member_cannot_admit_a_second_bridge() {
    let fixture = native_exec_fixture();
    let mut service = fixture.service();
    let context = words(fixture.address);
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
            &context,
            &mut service,
        )
        .unwrap();
    fixture.runtime.graph.lock().insert_member_wait(
        fixture.record,
        MemberWait::Signal(PendingSignalWait {
            kind: PendingSignalKind::Suspend,
            channel: Arc::new(WaitChannel {
                generation: ProcessWake::new(),
                mm: fixture.address.mm.raw().get(),
            }),
            deadline: None,
        }),
    );
    let result = entry.begin_service(
        carrick_core_abi::service::ServiceOperation::Crossing {
            ordinal: carrick_guest_arch::NativeOrdinal::new(115),
        },
        None,
    );
    let settled = entry.settle_service_exit(result, NativeServiceExit::Bridge);
    let fatal = crate::dispatch::native_service_completion(settled, entry.native_service_phase())
        .err()
        .expect("a second bridge cannot own a suspended member");
    assert_eq!(
        fatal.fatal_reason(),
        carrick_el1_abi::EntryBindingFatalReason::NativeServiceQuarantined
    );
    assert!(fixture.task.service_notice.take().unwrap().is_none());
    assert_eq!(carrick_el1_abi::Lifecycle::claimed_count(fixture.page), 0);
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
                demand: carrick_core_abi::service::CarrierDemand::Work,
            },
            None,
        );
        assert!(matches!(
            entry.settle_service_exit(result, NativeServiceExit::CarrierWork),
            Ok(NativeResume::Left(None))
        ));
    }

    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
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
        resumed.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Returned(result)) if result.raw() == COMPLETED as i64
    ));
}

#[cfg(test)]
fn publish_test_exec_reply<C: ProcessContext + 'static>(
    fixture: &NativeSignalFixture<C>,
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
fn publish_test_exec_reply_with<C: ProcessContext + 'static>(
    fixture: &NativeSignalFixture<C>,
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
fn publish_test_exec_reply_for<C: ProcessContext + 'static>(
    fixture: &NativeSignalFixture<C>,
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
        .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
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
    refused_exec_case(false);
}

#[cfg(test)]
#[test]
fn post_arm_exec_adoption_failure_is_sigsegv() {
    refused_exec_case(true);
}

#[cfg(test)]
#[test]
fn lost_exec_race_keeps_winner_signal_instead_of_sigsegv() {
    for adoption_failure in [false, true] {
        lost_exec_fatal_signal_case_for::<
            ParkedContextWords,
            carrick_mmu_core::x86::owner_mmu::X86Mmu,
        >(words, adoption_failure);
        lost_exec_fatal_signal_case_for::<
            carrick_el1_abi::Aarch64ParkedContext,
            carrick_mmu_core::owner_mmu::Aarch64Mmu,
        >(arm_words, adoption_failure);
    }
}

#[cfg(test)]
fn refused_exec_case(adoption_failure: bool) {
    refused_exec_case_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        adoption_failure,
    );
    refused_exec_case_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, adoption_failure);
}

#[cfg(test)]
fn refused_exec_case_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    adoption_failure: bool,
) {
    let _ = take_exec_cancellations();
    let fixture = native_exec_fixture_for::<C, B>(make_words);
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
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.begin_exec_service(
                test_exec_payload(b"/bin/static"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
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
        !adoption_failure,
    );
    if adoption_failure {
        // A valid sealed preparation reaches the production adopter after
        // the exec gate arms; a conflicting physical bind refuses adoption.
        let index = fixture.zone.spaces.find(successor_mm.raw()).unwrap();
        assert!(fixture.zone.spaces.bind_initial_root(
            index,
            successor_mm.raw(),
            0xd0_0000,
            0xd0_0000,
        ));
    }
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
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Left(None))
    ));
    assert!(entry.take_run_failure().is_none());
    assert_eq!(
        entry.take_root_exit().map(|status| status.raw()),
        Some(carrick_signal_core::policy::ExecPastNoReturn::SIGNAL.number()),
    );
    assert_eq!(take_exec_cancellations(), vec![113]);
    assert_eq!(fixture.task.mm.key.load(Ordering::Acquire), 1);
    assert!(fixture.zone.spaces.find(successor_mm.raw()).is_none());
}

#[cfg(test)]
fn lost_exec_fatal_signal_case_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    adoption_failure: bool,
) {
    let _ = take_exec_cancellations();
    let fixture = native_exec_fixture_for::<C, B>(make_words);
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
                &(fixture.make_words)(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.begin_exec_service(
                test_exec_payload(b"/bin/static"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let successor_mm = publish_test_exec_reply_with(
        &fixture,
        fixture.control,
        fixture.slot,
        119,
        0xc0_0000,
        false,
    );
    if adoption_failure {
        let index = fixture.zone.spaces.find(successor_mm.raw()).unwrap();
        assert!(fixture.zone.spaces.bind_initial_root(
            index,
            successor_mm.raw(),
            0xd0_0000,
            0xd0_0000,
        ));
    }
    // Simulate a concurrent SIGKILL upgrading the process cancellation cause
    // before the exec caller finishes adoption or retracts exec cancellation.
    fixture
        .page
        .process_exit_custody()
        .publish_cancellation(carrick_core::terminal::ProcessCancellation::FatalSignal);

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
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Left(None))
    ));
    assert!(entry.take_run_failure().is_none());
    assert_eq!(
        entry.take_root_exit().map(|status| status.raw()),
        Some(carrick_signal_core::policy::Signal::KILL.number()),
    );
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
            demand: carrick_core_abi::service::CarrierDemand::Work,
        }),
    )
}

fn add_service_sibling<C: ProcessContext + 'static>(
    fixture: &NativeSignalFixture<C>,
    operation: Option<carrick_core_abi::service::ServiceOperation>,
) -> ExecSibling {
    add_signal_sibling(fixture, operation, false)
}

// Prepare a real published birth without entering native registration.
fn prepare_signal_sibling<C: ProcessContext + 'static>(
    fixture: &NativeSignalFixture<C>,
    host_issued: bool,
) -> ExecSibling {
    let binding = ExecutionBinding {
        task: carrick_core_abi::EntryTaskKey::from_raw(42),
        generation: carrick_core_abi::SnapshotGeneration::from_raw(12),
        mm: carrick_core_abi::EntryMmKey::from_raw(1),
        thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(102),
    };
    // The host issues the sibling's tid in the shared namespace table before
    // registration claims it, as a production host-born thread does.
    fixture
        .zone
        .namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            ns.reserve_exact(42, ClaimKind::Thread).unwrap();
        });
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
    ExecSibling {
        task,
        control,
        slot,
        record,
        service_ticket: None,
    }
}

#[cfg(test)]
#[test]
fn register_thread_busy_keeps_birth_authenticable() {
    let fixture = native_exec_fixture();
    let sibling = prepare_signal_sibling(&fixture, true);
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
    let binding = crate::common_entry::execution_binding(sibling.task);
    let birth = sibling.control.host_birth_identity().unwrap();
    let writer = carrick_el1_abi::NativePendingCustody::try_admit(
        retain_member_control(sibling.control).unwrap(),
    )
    .unwrap();
    let before = {
        let state = fixture.registry.state.lock();
        (
            state.members.len(),
            state.records.len(),
            state
                .by_process
                .values()
                .map(|(_, members)| members.len())
                .sum::<usize>(),
        )
    };
    assert!(matches!(
        fixture.registry.register_thread(
            source,
            sibling.task,
            fixture.address,
            fixture.page,
            sibling.control
        ),
        Err(NativeProcessError::Busy)
    ));
    assert!(
        IssuedHostThread::authenticate(
            source,
            binding,
            41,
            fixture.page,
            sibling.control,
            sibling.record.id
        )
        .is_ok(),
        "Busy consumed the host birth before admission committed"
    );
    {
        let graph = fixture.runtime.graph.lock();
        let row = graph.owner.task(graph.root_key).unwrap();
        assert!(
            row.credentials_for(42).is_err(),
            "Busy published thread credentials"
        );
        assert_eq!(row.native().resources().members.len(), 1);
    }
    {
        let state = fixture.registry.state.lock();
        assert_eq!(
            (
                state.members.len(),
                state.records.len(),
                state
                    .by_process
                    .values()
                    .map(|(_, members)| members.len())
                    .sum::<usize>()
            ),
            before
        );
    }
    drop(writer);
    fixture
        .registry
        .register_thread(
            source,
            sibling.task,
            fixture.address,
            fixture.page,
            sibling.control,
        )
        .unwrap();
    {
        let graph = fixture.runtime.graph.lock();
        let row = graph.owner.task(graph.root_key).unwrap();
        assert!(row.credentials_for(42).is_ok());
        assert_eq!(row.native().resources().members.len(), 2);
    }
    let state = fixture.registry.state.lock();
    assert_eq!(
        (
            state.members.len(),
            state.records.len(),
            state
                .by_process
                .values()
                .map(|(_, members)| members.len())
                .sum::<usize>()
        ),
        (before.0 + 1, before.1 + 1, before.2 + 1)
    );
    assert!(
        !fixture.page.release_adopted_host_birth(birth),
        "birth must already be consumed exactly once"
    );
}

// Existing payload allocations must survive production admission unchanged.
#[cfg(test)]
#[test]
fn register_thread_preserves_existing_credential_storage() {
    use carrick_personality_linux::identity::TaskGid;

    let fixture = native_exec_fixture();
    let sibling = prepare_signal_sibling(&fixture, true);
    let before = {
        let mut graph = fixture.runtime.graph.lock();
        let root = graph.root_key;
        let row = graph.owner.task_mut(root).unwrap();
        for tid in 43..47 {
            row.threads.spawn_thread(41, tid).unwrap();
        }
        row.threads.threads.reserve(1);
        for (index, thread) in row.threads.threads.iter_mut().enumerate() {
            thread.credentials.groups = (0..4096 + index * 257)
                .map(|group| TaskGid::new((index * 10000 + group) as u32))
                .collect();
            thread.credentials.groups_installed = true;
            thread.comm = [index as u8 + 1; 16];
        }
        (
            row.threads.threads.as_ptr(),
            row.threads.threads.capacity(),
            row.threads
                .threads
                .iter()
                .map(|thread| {
                    (
                        thread.credentials.groups.as_ptr(),
                        thread.credentials.groups.capacity(),
                    )
                })
                .collect::<alloc::vec::Vec<_>>(),
        )
    };
    fixture
        .registry
        .register_thread(
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            fixture.page,
            sibling.control,
        )
        .unwrap();
    let graph = fixture.runtime.graph.lock();
    let row = graph.owner.task(graph.root_key).unwrap();
    assert_eq!(
        row.threads.threads.as_ptr(),
        before.0,
        "registration replaced unrelated thread credential storage"
    );
    assert_eq!(row.threads.threads.capacity(), before.1);
    assert_eq!(row.threads.threads.len(), before.2.len() + 1);
    for (index, (thread, storage)) in row.threads.threads.iter().zip(&before.2).enumerate() {
        assert_eq!(
            thread.credentials.groups.as_ptr(),
            storage.0,
            "registration copied an existing supplementary-group payload"
        );
        assert_eq!(thread.credentials.groups.capacity(), storage.1);
        assert_eq!(thread.credentials.groups.len(), 4096 + index * 257);
        assert!(
            thread
                .credentials
                .groups
                .iter()
                .enumerate()
                .all(|(group, gid)| *gid == TaskGid::new((index * 10000 + group) as u32))
        );
        assert_eq!(thread.comm, [index as u8 + 1; 16]);
    }
    let child = row.threads.threads.last().unwrap();
    assert_eq!(child.tid, 42);
    assert_eq!(child.credentials, row.threads.threads[0].credentials);
    assert_ne!(child.credentials.groups.as_ptr(), before.2[0].0);
    assert_eq!(child.comm, row.threads.threads[0].comm);
}

fn add_signal_sibling<C: ProcessContext + 'static>(
    fixture: &NativeSignalFixture<C>,
    operation: Option<carrick_core_abi::service::ServiceOperation>,
    host_issued: bool,
) -> ExecSibling {
    let ExecSibling {
        task,
        control,
        slot,
        record,
        ..
    } = prepare_signal_sibling(fixture, host_issued);
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
                &(fixture.make_words)(fixture.address),
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
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
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

#[cfg(test)]
fn park_anonymous_sibling(
    fixture: &NativeSignalFixture,
    sibling: &ExecSibling,
) -> carrick_sched_core::object_wait::ObjectWaitKey {
    park_anonymous_sibling_on(
        fixture,
        sibling,
        carrick_sched_core::spaces::notification::SpaceWaitCause::Editor,
    )
}

#[cfg(test)]
fn park_anonymous_sibling_on(
    fixture: &NativeSignalFixture,
    sibling: &ExecSibling,
    cause: carrick_sched_core::spaces::notification::SpaceWaitCause,
) -> carrick_sched_core::object_wait::ObjectWaitKey {
    use carrick_core::wait::{
        EditWaitOutcome, ObjectParkRequest, coordinate_anonymous_edit_wait, park_object_record,
    };
    use carrick_sched_core::object_wait::ObjectWaitError;

    assert!(fixture.zone.mark_native_owned(sibling.record.id));
    let space = fixture.zone.space_entry(NonZeroU64::MIN).unwrap();
    space
        .admit_notifications(
            NonZeroU64::MIN,
            &carrick_sched_core::ShortLockSpin,
            &|effects| {
                crate::sched::object_wait::deliver_completion(fixture.zone, sibling.slot, effects)
            },
        )
        .unwrap();
    let notifications = space.notifications(NonZeroU64::MIN).unwrap();
    let key = notifications.key(cause);
    let outcome = coordinate_anonymous_edit_wait(
        &notifications,
        None,
        || Some(Some(cause)),
        |key, snapshot, operation| {
            let request = ObjectParkRequest::from_locked_snapshot(key, snapshot, operation, None);
            let parked = park_object_record(
                fixture.zone,
                sibling.slot,
                request,
                &|effects| {
                    crate::sched::object_wait::deliver_completion(
                        fixture.zone,
                        sibling.slot,
                        effects,
                    )
                },
                || {
                    let record = fixture
                        .zone
                        .slot(sibling.slot)
                        .current()
                        .or_else(|| fixture.zone.slot(sibling.slot).host_record())
                        .ok_or(ObjectWaitError::Stale)?;
                    // SAFETY: this fixture owns the selected sibling record until park publishes.
                    *unsafe { fixture.zone.record(record).ctx_mut() } = words(fixture.address);
                    Ok((record, false))
                },
            );
            if let Err((error, _)) = &parked {
                panic!("anonymous sibling park failed: {error:?}");
            }
            parked
        },
    );
    let EditWaitOutcome::Parked(_) = outcome else {
        panic!("anonymous sibling must enter the production object wait");
    };
    assert_eq!(
        fixture
            .zone
            .object_queue_census(key.index())
            .unwrap()
            .waiters,
        1
    );
    let census = fixture
        .zone
        .record(sibling.record.id)
        .object_wait_census()
        .unwrap();
    assert_eq!(
        (
            census.queue,
            census.generation,
            census.operation,
            census.operation_generation,
        ),
        (
            key.index(),
            key.generation(),
            carrick_sched_core::object_wait::OperationToken::anonymous_edit(key)
                .unwrap()
                .index(),
            key.generation(),
        )
    );
    assert!(matches!(
        fixture.zone.record(sibling.record.id).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    key
}

#[cfg(test)]
#[test]
fn settlement_doorbell_failure_and_exit_group_preserve_single_flight() {
    use carrick_core_abi::{
        ReservationMm, ReservationRange, SettlementClaim, SettlementDoorbellAnswer,
        SettlementDoorbellReply,
    };
    use carrick_el1::memory::reservations::{Layout, SharedReservations};
    use carrick_hal::return_settlement::{SettlementDoorbellService, service_settlement_doorbell};
    use carrick_sched_core::spaces::notification::{SpaceReleaseVenue, SpaceWaitCause};
    use std::cell::Cell;

    struct Doorbell<'a> {
        table: &'a SharedReservations,
        zone: &'a ZoneTables<ParkedContextWords>,
        index: usize,
        calls: usize,
        releases: usize,
        body: &'a mut dyn FnMut() -> Result<SettlementDoorbellAnswer, &'static str>,
    }
    impl SettlementDoorbellService for Doorbell<'_> {
        type Error = &'static str;
        fn settle(&mut self, mm: ReservationMm) -> Result<SettlementDoorbellAnswer, &'static str> {
            self.calls += 1;
            assert!(
                self.table
                    .lock(self.index, mm)
                    .unwrap()
                    .claim_return_settlement(1)
                    .is_none(),
                "no takeover during service"
            );
            (self.body)()
        }
        fn release(
            &mut self,
            mm: ReservationMm,
            claim: SettlementClaim,
        ) -> Result<(), &'static str> {
            if self.table.release_return_settlement(claim) {
                self.releases += 1;
                if let Some(source) = self
                    .zone
                    .space_entry(NonZeroU64::new(mm.raw()).unwrap())
                    .and_then(|entry| entry.live_notifications().ok())
                {
                    fn deliver(
                        zone: &ZoneTables<ParkedContextWords>,
                        _: carrick_sched_core::Waker,
                        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                            '_,
                            ParkedContextWords,
                        >,
                    ) {
                        crate::sched::object_wait::deliver_host_completion(zone, effects);
                    }
                    SpaceReleaseVenue {
                        zone: self.zone,
                        waker: carrick_sched_core::Waker::Host,
                        deliver:
                            carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(
                                deliver,
                            ),
                    }
                    .publish(source.reserve(SpaceWaitCause::Reservations));
                }
            }
            Ok(())
        }
    }
    for group_exit in [false, true] {
        let fixture = native_exec_fixture();
        let sibling = add_signal_sibling(&fixture, None, false);
        let region = carrick_test_support::TestEl1Region::zeroed();
        // SAFETY: this aligned, zeroed region owns the complete production
        // reservation table for the entire decoded-doorbell schedule.
        let table = unsafe {
            &*region
                .as_ptr()
                .add(carrick_el1_abi::EL1_RESERVATIONS_OFFSET as usize)
                .cast::<SharedReservations>()
        };
        let mm = ReservationMm::new(1).unwrap();
        let index = fixture.zone.spaces.find(mm.raw()).unwrap().index();
        let layout = Layout {
            heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
            arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
            brk: 0x1000,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        };
        table.publish(index, mm, layout).unwrap();
        table.lock(index, mm).unwrap().finish_import().unwrap();
        let claim = table
            .lock(index, mm)
            .unwrap()
            .claim_return_settlement(0)
            .unwrap();
        let waiter = if group_exit {
            None
        } else {
            Some(park_anonymous_sibling_on(
                &fixture,
                &sibling,
                SpaceWaitCause::Reservations,
            ))
        };
        let fail_once = Cell::new(!group_exit);
        let mut body = || {
            if group_exit {
                // Another live thread publishes the claimant's real group
                // terminal decision while the carrier entry owns its claim.
                let mut physical = fixture.service();
                physical.waker_slot = sibling.slot;
                let mut entry = fixture
                    .runtime
                    .enter_registered(
                        fixture.registry,
                        BornInZoneSource {
                            zone: fixture.zone,
                            slot: sibling.slot,
                        },
                        sibling.task,
                        fixture.address,
                        &words(fixture.address),
                        &mut physical,
                    )
                    .unwrap();
                assert!(matches!(
                    entry.exit_group(23),
                    LifecycleOutcome::Transferred { .. }
                ));
                assert!(entry.take_run_failure().is_none());
                assert!(fixture.control.host_exit_requested());
                assert!(fixture.page.exit_wait().is_some());
            }
            if fail_once.replace(false) {
                Err("injected doorbell service failure")
            } else {
                Ok(SettlementDoorbellReply::Settled.into())
            }
        };
        let mut doorbell = Doorbell {
            table,
            zone: fixture.zone,
            index,
            calls: 0,
            releases: 0,
            body: &mut body,
        };
        let answer = service_settlement_doorbell(&mut doorbell, mm, claim, true);
        assert_eq!(doorbell.releases, 1, "the actual carrier epilogue ran once");
        assert!(!table.lock(index, mm).unwrap().return_settlement_claimed());
        if let Some(key) = waiter {
            assert_eq!(answer, Err("injected doorbell service failure"));
            assert_eq!(
                fixture
                    .zone
                    .object_queue_census(key.index())
                    .unwrap()
                    .waiters,
                0
            );
            assert!(!matches!(
                fixture.zone.record(sibling.record.id).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));
            assert!(
                fixture
                    .zone
                    .record(sibling.record.id)
                    .has_object_operation(),
                "the next refuser retains its original operation"
            );
            let next = table
                .lock(index, mm)
                .unwrap()
                .claim_return_settlement(1)
                .unwrap();
            // A late duplicate from the failed crossing cannot release the
            // next driver's exact claim or publish another wake.
            let source = fixture
                .zone
                .space_entry(NonZeroU64::MIN)
                .unwrap()
                .live_notifications()
                .unwrap();
            let before = source.observe(SpaceWaitCause::Reservations);
            service_settlement_doorbell(&mut doorbell, mm, claim, false).unwrap();
            assert_eq!(source.observe(SpaceWaitCause::Reservations), before);
            assert!(table.lock(index, mm).unwrap().return_settlement_claimed());
            assert_eq!(
                service_settlement_doorbell(&mut doorbell, mm, next, true),
                Ok(SettlementDoorbellReply::Settled.into())
            );
            assert_eq!((doorbell.calls, doorbell.releases), (2, 2));
        } else {
            assert_eq!(answer, Ok(SettlementDoorbellReply::Settled.into()));
            assert_eq!(
                doorbell.calls, 1,
                "terminal publication never starts a second driver"
            );
            table.lock(index, mm).unwrap().retire().unwrap();
            let successor = ReservationMm::new(2).unwrap();
            table.publish(index, successor, layout).unwrap();
            table
                .lock(index, successor)
                .unwrap()
                .finish_import()
                .unwrap();
            let next = table
                .lock(index, successor)
                .unwrap()
                .claim_return_settlement(0)
                .unwrap();
            service_settlement_doorbell(&mut doorbell, mm, claim, false).unwrap();
            assert_eq!((doorbell.calls, doorbell.releases), (1, 1));
            assert!(
                table
                    .lock(index, successor)
                    .unwrap()
                    .return_settlement_claimed()
            );
            assert!(table.release_return_settlement(next));
        }
    }
}

#[cfg(test)]
mod anonymous_wait_cancellation_tests {
    use super::*;

    #[test]
    fn caught_signal_entry_interrupts_parked_anonymous_edit_without_eintr() {
        let fixture = native_exec_fixture();
        fixture.install_sigint_handler(false);
        let sibling = add_signal_sibling(&fixture, None, false);
        let key = park_anonymous_sibling(&fixture, &sibling);
        let binding = crate::common_entry::execution_binding(sibling.task);
        let event = carrick_el1_abi::ExternalSignalRecord::new(
            carrick_core_abi::EntryEventIdentity::from_binding(binding),
            binding,
            sibling.record,
            carrick_el1_abi::SignalEventGeneration::new(NonZeroU64::MIN),
            carrick_signal_core::policy::Signal::from_number(2).unwrap(),
            carrick_el1_abi::ExternalSignalSource::InZoneIpc,
        );
        let mut service = fixture.service();
        assert!(
            fixture
                .registry
                .admit_external_event(fixture.zone, event, fixture.slot, &mut service)
                .unwrap()
        );
        assert_eq!(
            fixture
                .zone
                .object_queue_census(key.index())
                .unwrap()
                .waiters,
            0,
            "the real signal entry must detach the anonymous edit waiter"
        );
        assert_eq!(
            fixture.zone.record(sibling.record.id).handback(),
            Some(carrick_sched_core::Handback::Signal),
            "caught signal retains the operation for syscall-instruction replay"
        );
        assert!(
            fixture
                .zone
                .record(sibling.record.id)
                .has_object_operation(),
            "signal interruption cannot synthesize EINTR or discard the anonymous call"
        );
    }

    #[test]
    fn anonymous_release_resumes_through_syscall_replay() {
        let fixture = native_exec_fixture();
        let sibling = add_signal_sibling(&fixture, None, false);
        let key = park_anonymous_sibling(&fixture, &sibling);
        fixture
            .zone
            .object_wait_with_completion(key, &carrick_sched_core::ShortLockSpin, &|effects| {
                crate::sched::object_wait::deliver_completion(fixture.zone, sibling.slot, effects)
            })
            .unwrap()
            .notify_object(sibling.slot, &mut Default::default())
            .unwrap();
        assert_eq!(
            fixture.zone.switch_in_full(sibling.slot).unwrap().record,
            sibling.record.id
        );
        let retained = fixture.zone.record(sibling.record.id);
        assert!(!retained.has_adapter_operation());
        // SAFETY: the production scheduler selected this exact sibling record.
        let saved = unsafe { fixture.runtime.record_binding(sibling.record) }
            .unwrap()
            .words;
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: sibling.slot,
        };
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                sibling.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(
            matches!(
                entry.resume_checkpoint(|_| Ok(None)),
                Ok(NativeResume::RetrySavedSyscall | NativeResume::RetrySyscall)
            ),
            "an anonymous release must replay the call, never return its ordinal as a result"
        );
        assert_eq!(
            entry.resume_context().syscall_return(),
            saved.syscall_return()
        );
        assert!(!retained.has_adapter_operation());
    }

    #[test]
    fn anonymous_host_handback_preserves_replay_domain() {
        let fixture = native_exec_fixture();
        let sibling = add_signal_sibling(&fixture, None, false);
        let key = park_anonymous_sibling(&fixture, &sibling);
        assert_eq!(
            fixture.zone.claim_for_host(
                sibling.record,
                None,
                carrick_sched_core::Handback::Control,
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            ),
            carrick_sched_core::HostClaim::Claimed,
        );
        let record = fixture.zone.live(sibling.record).unwrap();
        assert_eq!(
            fixture
                .zone
                .object_queue_census(key.index())
                .unwrap()
                .waiters,
            0
        );
        assert!(record.has_object_operation());
        assert!(
            !record.has_adapter_operation(),
            "anonymous replay must not enter IPC cancellation or host IPC resume"
        );
        // SAFETY: claim_for_host above owns the exact, now-unlinked record.
        let token = unsafe { record.take_object_operation() }.unwrap();
        assert!(token.kind().replays_syscall());
        assert!(carrick_el1::substrate::ipc::from_sched_token(token).is_none());
        fixture.zone.free_record(sibling.record.id);
    }

    #[test]
    fn exit_group_entry_cancels_parked_anonymous_edit_without_effects() {
        let fixture = native_exec_fixture();
        let sibling = add_signal_sibling(&fixture, None, false);
        let key = park_anonymous_sibling(&fixture, &sibling);
        let reservation_revision = fixture
            .zone
            .space_entry(NonZeroU64::MIN)
            .unwrap()
            .notifications(NonZeroU64::MIN)
            .unwrap()
            .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations);
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
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
            entry.exit_group(23),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_run_failure().is_none());
        assert_eq!(
            fixture
                .zone
                .object_queue_census(key.index())
                .unwrap()
                .waiters,
            0,
            "the real exit entry must unlink the anonymous waiter"
        );
        assert!(
            !fixture
                .zone
                .record(sibling.record.id)
                .has_object_operation(),
            "exit cancellation must release scheduler-owned anonymous custody"
        );
        assert!(
            fixture.zone.live(sibling.record).is_none(),
            "exit cancellation must retire the unpinned anonymous record"
        );
        assert_eq!(
            fixture
                .zone
                .space_entry(NonZeroU64::MIN)
                .unwrap()
                .notifications(NonZeroU64::MIN)
                .unwrap()
                .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations),
            reservation_revision,
            "terminal cancellation cannot publish an anonymous edit"
        );
    }

    #[test]
    fn exit_group_keeps_pipe_pin_distinct_from_anonymous_replay() {
        let fixture = native_exec_fixture();
        let sibling = add_signal_sibling(&fixture, None, false);
        let key = park_anonymous_sibling(&fixture, &sibling);
        use carrick_el1_abi::ipc::{
            IpcBacking, IpcMmKey, IpcOpKind, IpcOperation, IpcTaskKey, IpcUserVa, WriteProgress, fd,
        };
        let ipc = Box::leak(Box::new(std::sync::Arc::new(
            carrick_kernel::el1_ipc::HostIpc::with_limits(
                1 << 20,
                carrick_el1_abi::ipc::IpcLimits::ZONE,
            )
            .unwrap(),
        )));
        let object = ipc.create_pipe(65536).unwrap();
        let table = ipc.create_table(64, 64).unwrap();
        let description = ipc
            .admit_description(fd::Description::new(
                IpcBacking::Pipe {
                    object,
                    end: carrick_el1_abi::ipc::pipe::End::Reader,
                }
                .encode(),
                fd::AccessMode::ReadOnly,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        description.install(table, fd::Fd(0), false).unwrap();
        drop(description);
        let region = ipc.region();
        let (pin, _) = region
            .fd(carrick_sched_core::ShortLockSpin)
            .pin(table, fd::Fd(0))
            .unwrap();
        let binding = crate::common_entry::execution_binding(fixture.task);
        let ipc_token = region
            .begin_operation(IpcOperation {
                kind: IpcOpKind::PipeRead,
                pin: pin.into_raw(),
                object: object.to_raw(),
                task: IpcTaskKey(binding.task.raw()),
                mm: IpcMmKey(binding.mm.raw()),
                buf: IpcUserVa(0x10000),
                progress: WriteProgress::new(8),
                ..IpcOperation::EMPTY
            })
            .unwrap();
        let ipc_token = carrick_el1::substrate::ipc::to_sched_token(ipc_token).unwrap();
        // SAFETY: the fixture owns the leader's executing record. This is the
        // same retained IPC pin a signal handler carries into exit_group.
        unsafe {
            fixture
                .zone
                .record(fixture.record.id)
                .restore_object_operation(ipc_token)
        }
        .unwrap();
        assert!(
            fixture
                .zone
                .record(fixture.record.id)
                .has_adapter_operation()
        );
        assert!(
            !fixture
                .zone
                .record(sibling.record.id)
                .has_adapter_operation()
        );
        // Only the pending operation retains the endpoint description.
        assert!(
            region
                .fd(carrick_sched_core::ShortLockSpin)
                .close(table, fd::Fd(0))
                .unwrap()
                .is_none()
        );
        let reservation_revision = fixture
            .zone
            .space_entry(NonZeroU64::MIN)
            .unwrap()
            .notifications(NonZeroU64::MIN)
            .unwrap()
            .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations);
        let source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        let mut service = fixture.service();
        service.native_ipc = Some(region);
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
            entry.exit_group(23),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_run_failure().is_none());
        drop(entry);
        assert!(
            fixture
                .zone
                .record(fixture.record.id)
                .has_adapter_operation(),
            "terminal IPC custody must survive until the adapter releases its pin"
        );
        assert_eq!(
            fixture.zone.claim_for_host(
                fixture.record,
                None,
                carrick_sched_core::Handback::Cancelled,
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            ),
            carrick_sched_core::HostClaim::Claimed
        );
        // SAFETY: the production cancellation claim owns this exact unlinked record.
        let token = unsafe {
            fixture
                .zone
                .record(fixture.record.id)
                .take_object_operation()
        }
        .unwrap();
        assert_eq!(
            token.kind(),
            carrick_sched_core::object_wait::OperationKind::Adapter
        );
        crate::ipc::retire_native_operation(
            &region,
            fixture.zone,
            fixture.slot,
            fixture.task,
            binding,
            token,
        )
        .unwrap();
        fixture.zone.free_record(fixture.record.id);
        assert!(fixture.zone.live(fixture.record).is_none());

        assert_eq!(
            fixture
                .zone
                .object_queue_census(key.index())
                .unwrap()
                .waiters,
            0,
            "the real exit entry must unlink the anonymous waiter"
        );
        assert!(
            !fixture
                .zone
                .record(sibling.record.id)
                .has_object_operation(),
            "exit cancellation must release scheduler-owned anonymous custody"
        );
        assert!(
            fixture.zone.live(sibling.record).is_none(),
            "exit cancellation must retire the unpinned anonymous record"
        );
        assert_eq!(
            fixture
                .zone
                .space_entry(NonZeroU64::MIN)
                .unwrap()
                .notifications(NonZeroU64::MIN)
                .unwrap()
                .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations),
            reservation_revision,
            "terminal cancellation cannot publish an anonymous edit"
        );
    }

    #[test]
    fn exec_entry_cancels_parked_anonymous_edit_without_effects() {
        let fixture = native_exec_fixture();
        let sibling = add_signal_sibling(&fixture, None, false);
        let key = park_anonymous_sibling(&fixture, &sibling);
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
                entry.begin_exec_service(
                    test_exec_payload(b"/bin/static"),
                    None,
                    NativeServiceCall::new(
                        carrick_guest_arch::NativeOrdinal::new(221),
                        &carrick_el1_abi::Counters::new()
                    )
                ),
                Ok(NativeResume::Left(None))
            ));
            assert!(entry.take_handoff_receipt().is_some());
        }
        let _successor =
            publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 0x1846, 0xa0_0000);
        let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
        assert_eq!(selected.record, fixture.record.id);
        // SAFETY: the production service completion selected this exact root record.
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
            entry.resume_checkpoint(|_| Ok(None)),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_run_failure().is_none());
        assert_eq!(
            fixture
                .zone
                .object_queue_census(key.index())
                .unwrap()
                .waiters,
            0,
            "the real exec entry must unlink the anonymous waiter"
        );
        assert!(
            !fixture
                .zone
                .record(sibling.record.id)
                .has_object_operation(),
            "exec cancellation must release scheduler-owned anonymous custody"
        );
        assert!(
            fixture.zone.live(sibling.record).is_none(),
            "exec cancellation must retire the unpinned anonymous record"
        );
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
                member.resume_checkpoint(|_| Ok(None)),
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
        assert!(matches!(root.resume_checkpoint(|_| Ok(None)),
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
        let result = entry.begin_exec_service(
            test_exec_payload(b"/bin/static"),
            None,
            crate::native_process_runtime::NativeServiceCall::new(
                carrick_guest_arch::NativeOrdinal::new(221),
                &carrick_el1_abi::Counters::new(),
            ),
        );
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
    let resumed = entry.resume_checkpoint(|_| Ok(None));
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
                    demand: carrick_core_abi::service::CarrierDemand::Work,
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
            entry.begin_exec_service(
                test_exec_payload(b"/bin/static"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
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
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Left(None))
    ));
    assert_eq!(fixture.task.mm.key.load(Ordering::Acquire), 1);
    assert!(fixture.zone.spaces.find(successor_mm.raw()).is_some());
    assert!(fixture.page.exit_wait().is_some());
    assert!(fixture.page.cancel_host_birth_claim(host_birth).is_some());
}

/// #2235: a process's record names its task key; its threads see their
/// namespace-visible tids. A carrier whose task keys are not namespace pids
/// (the x86 KVM run issues host-scale keys, its children see pid 2, ...)
/// still execs: the sole-member check compares the record against the
/// entry's own task key, never against a visible tid in another domain.
#[cfg(test)]
#[test]
fn exec_succeeds_when_task_keys_are_not_namespace_tids() {
    let fixture = NativeSignalFixture::new_with_context::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        ExecutionBinding {
            task: carrick_core_abi::EntryTaskKey::from_raw(198_057),
            generation: carrick_core_abi::SnapshotGeneration::from_raw(11),
            mm: carrick_core_abi::EntryMmKey::from_raw(1),
            thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(101),
        },
        carrick_core_abi::EntryTaskKey::from_raw(198_057),
        carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(11).unwrap()),
        words,
    );
    // The namespace view: the process and its thread are pid 2.
    fixture.task.publish_visible_pid(2);
    // SAFETY: the fixture's sole member; nothing else reads its slot yet.
    unsafe { fixture.control.promote_exec_identity_owned(2) };
    {
        let mut graph = fixture.runtime.graph.lock();
        let key = graph.owner.tasks().values().next().unwrap().key();
        let row = graph.owner.task_mut(key).unwrap();
        row.metadata_mut().namespace_pid = 2;
        for thread in &mut row.threads.threads {
            thread.tid = 2;
        }
    }
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
            entry.begin_exec_service(
                test_exec_payload(b"/bin/static"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let successor_mm =
        publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 67, 0x9a_0000);
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
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
    assert!(entry.take_run_failure().is_none());
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        successor_mm.raw(),
        "the exec committed its successor rather than killing the caller"
    );
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
            entry.begin_exec_service(
                test_exec_payload(b"/bin/static"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
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
        entry.resume_checkpoint(|_| Ok(None)),
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
            entry.begin_exec_service(
                test_exec_payload(b"/bin/static"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
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
            entry.resume_checkpoint(|_| Ok(None)),
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
    let resumed = entry.resume_checkpoint(|_| Ok(None));
    let resumed_kind = match &resumed {
        Ok(NativeResume::NoPending) => "no-pending",
        Ok(NativeResume::RetrySavedSyscall) => "retry-saved-syscall",
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
            root.begin_exec_service(
                test_exec_payload(b"/bin/winner"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
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
            loser.begin_exec_service(
                test_exec_payload(b"/bin/loser"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
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
            root.resume_checkpoint(|_| Ok(None)),
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
        root.resume_checkpoint(|_| Ok(None)),
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
    exec_drain_is_upgraded_by_terminal_sibling_for::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(words, signal);
    exec_drain_is_upgraded_by_terminal_sibling_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, signal);
}

#[cfg(test)]
fn exec_drain_is_upgraded_by_terminal_sibling_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    signal: Option<u8>,
) {
    let _ = take_exec_cancellations();
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let sibling = add_service_sibling(&fixture, None);
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
                &(fixture.make_words)(fixture.address),
                &mut root_service,
            )
            .unwrap();
        assert!(matches!(
            root.begin_exec_service(
                test_exec_payload(b"/bin/replaced"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
            Ok(NativeResume::Left(None))
        ));
        assert!(root.take_handoff_receipt().is_some());
    }
    let _successor = publish_test_exec_reply_with(
        &fixture,
        fixture.control,
        fixture.slot,
        181,
        0xf0_0000,
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
            root.resume_checkpoint(|_| Ok(None)),
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
                &(fixture.make_words)(fixture.address),
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
    assert_eq!(terminator.take_root_exit(), Some(expected));
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

/// Missing cwd is the other access-admission refusal from #1409. Exercise
/// the real exec and host-file entries with production host-root admission,
/// a non-1 namespace root and no carrier ticket.
#[cfg(test)]
#[test]
fn root_exec_access_refusal_is_counted_before_service_publication() {
    let fixture = NativeSignalFixture::admit_host_root(
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
    let counters = Box::leak(Box::new(carrick_el1_abi::Counters::new()));
    let mut service = fixture.service();
    let mut root = fixture
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
    assert!(root.is_root_process());
    // Matching the stored root key is insufficient when its generation no
    // longer names an admitted owner row. Missing authority must not turn a
    // descendant refusal into evidence attributed to the initial process.
    let admitted_key = root.key;
    let stale_key = TaskKey {
        serial: TaskSerial::from_registry_allocation(NonZeroU64::new(u64::MAX).unwrap()),
        ..admitted_key
    };
    root.key = stale_key;
    fixture.runtime.graph.lock().root_key = stale_key;
    assert!(!root.is_root_process());
    root.key = admitted_key;
    fixture.runtime.graph.lock().root_key = admitted_key;
    // Production root admission retains host filesystem authority, even
    // when register_root transfers execution to the native scheduler owner.
    assert!(root.owns_descriptor_namespace());
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .owner
            .task(root.key)
            .unwrap()
            .fs
            .is_none()
    );
    let path = b"/lib/libc.so.6";
    let mut open =
        alloc::vec![0u8; carrick_core_abi::host_file::record_len(path.len(), 0).unwrap()];
    carrick_core_abi::host_file::encode(
        &mut open,
        carrick_core_abi::host_file::HostFileHeader {
            op: carrick_core_abi::host_file::HostFileOp::Openat,
            table: [1, 1, 1],
            fd: -100,
            flags: 0,
            args: [0; 4],
        },
        path,
        0,
    )
    .unwrap();
    // This is the same shared service entry the CPL0 loader binding needs.
    // Reject unknown pathname authority before any service can observe the
    // table selector; neither a guessed cwd nor the serving task may supply it.
    assert!(matches!(
        root.begin_host_file_service(open.into_boxed_slice(), None, true, None, false,
            NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(257), counters)),
        Ok(NativeResume::Returned(result))
            if result.raw() == carrick_syscall_abi::LINUX_ENOSYS.guest_retval()
    ));
    assert_eq!(counters.refused[257].load(Ordering::Relaxed), 1);
    assert_eq!(counters.refused_child[257].load(Ordering::Relaxed), 0);
    assert!(root.take_handoff_receipt().is_none());
    assert!(fixture.task.service_notice.take().unwrap().is_none());
    for ordinal in [221, 281, 600] {
        assert!(matches!(
            root.begin_exec_service(test_exec_payload(b"/bin/static"), None, NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(ordinal), counters)),
            Ok(NativeResume::Returned(result)) if result.raw() == carrick_syscall_abi::LINUX_ENOSYS.guest_retval()
        ));
        let bucket = ordinal.min(512) as usize;
        assert_eq!(counters.refused[bucket].load(Ordering::Relaxed), 1);
        assert_eq!(counters.refused_child[bucket].load(Ordering::Relaxed), 0);
        assert_eq!(counters.venue_refused[bucket].load(Ordering::Relaxed), 0);
        assert!(root.take_handoff_receipt().is_none());
        assert!(fixture.task.service_notice.take().unwrap().is_none());
    }
    // A vanished caller is an ordinary ESRCH, not a routing refusal.
    root.calling_tid = u32::MAX;
    assert!(matches!(
        root.begin_exec_service(test_exec_payload(b"/bin/static"), None, NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(221), counters)),
        Ok(NativeResume::Returned(result)) if result.raw() == carrick_syscall_abi::LINUX_ESRCH.guest_retval()
    ));
    assert_eq!(counters.refused[221].load(Ordering::Relaxed), 1);
}

/// #1392 (supersedes the #905 refusal): a native caller's exec and path
/// crossings carry its own ring credentials and cwd by value, so a ring
/// set*id or chdir changes what the carrier checks instead of refusing the
/// call. The access context is read from the caller's task row at service
/// time.
#[cfg(test)]
#[test]
fn native_child_exec_after_ring_setuid_carries_the_new_credentials() {
    let counters = Box::leak(Box::new(carrick_el1_abi::Counters::new()));
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
        child.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
    let decoded = |bytes: &[u8]| {
        let (context, rest) = carrick_core_abi::host_file::AccessContext::decode(bytes).unwrap();
        assert!(rest.is_empty());
        (context.ids.fsuid, context.ids.euid, context.cwd.to_vec())
    };
    assert_eq!(
        decoded(
            &child
                .caller_access(NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    counters
                ))
                .unwrap()
        ),
        (0, 0, b"/".to_vec())
    );
    // Review #1409 (1): the carrier models file capabilities from fsuid
    // alone, so a uid-0 caller that drops CAP_DAC_OVERRIDE is refused
    // (counted ENOSYS, no crossing): it can never open another owner's 0600
    // file as a DAC-overriding root.
    {
        use carrick_personality_linux::identity::{LinuxCapabilitySet, TaskCapabilities};
        let mut dropped = TaskCapabilities::FULL;
        dropped
            .effective
            .remove(LinuxCapabilitySet::CAP_DAC_OVERRIDE);
        child.capset(0, dropped).unwrap();

        let mut open = alloc::vec![0u8; carrick_core_abi::host_file::record_len(15, 0).unwrap()];
        carrick_core_abi::host_file::encode(
            &mut open,
            carrick_core_abi::host_file::HostFileHeader {
                op: carrick_core_abi::host_file::HostFileOp::Openat,
                table: [1, 1, 1],
                fd: -100,
                flags: 0,
                args: [0; 4],
            },
            b"/home/u/private",
            0,
        )
        .unwrap();
        assert!(matches!(
            child.begin_host_file_service(open.into_boxed_slice(), None, true, None, false, crate::native_process_runtime::NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(56), counters)),
            Ok(NativeResume::Returned(result))
                if result.raw() == carrick_syscall_abi::LINUX_ENOSYS.guest_retval()
        ));
        assert_eq!(counters.refused[56].load(Ordering::Relaxed), 1);
        assert_eq!(counters.refused_child[56].load(Ordering::Relaxed), 1);
        assert!(matches!(
            child.begin_exec_service(test_exec_payload(b"/bin/static"), None, crate::native_process_runtime::NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(221), counters)),
            Ok(NativeResume::Returned(result))
                if result.raw() == carrick_syscall_abi::LINUX_ENOSYS.guest_retval()
        ));
        assert_eq!(counters.refused[221].load(Ordering::Relaxed), 1);
        assert_eq!(counters.refused_child[221].load(Ordering::Relaxed), 1);
        assert_eq!(counters.venue_refused[56].load(Ordering::Relaxed), 0);
        assert_eq!(counters.venue_refused[221].load(Ordering::Relaxed), 0);
        child.capset(0, TaskCapabilities::FULL).unwrap();
    }
    child.set_uid(1000).unwrap();
    assert_eq!(
        decoded(
            &child
                .caller_access(NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    counters
                ))
                .unwrap()
        ),
        (1000, 1000, b"/".to_vec())
    );
    assert!(
        !matches!(
            child.begin_exec_service(test_exec_payload(b"/bin/static"), None, crate::native_process_runtime::NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(221), counters)),
            Ok(NativeResume::Returned(result))
                if result.raw() == carrick_syscall_abi::LINUX_ENOSYS.guest_retval()
        ),
        "the exec is served under the caller's own credentials, not refused"
    );
}

/// #2206 review P0-2: a fork child's served `fchdir` lands in its own ring
/// row through the runtime's one cwd writer (the host-file completion's
/// `complete_chdir`), not a hand-built cwd. Its next relative call carries
/// that cwd to the carrier, while its live parent's cwd stays where it was.
#[cfg(test)]
#[test]
fn native_child_fchdir_completion_moves_only_the_childs_cwd() {
    use carrick_core_abi::host_file::{AccessContext, HostFileOp, HostFileRequestView};
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_personality_linux::native_host_file::{
        DescriptionAccess, HostFileCall, HostFileStage, NativeDescriptor, NativeNamespace,
    };
    let counters = Box::leak(Box::new(carrick_el1_abi::Counters::new()));
    // The root forks one child, then parks in `wait4`: both stay live.
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let root_key = fixture.runtime.graph.lock().root_key;
    let cwd = |key| {
        let graph = fixture.runtime.graph.lock();
        let task = graph.owner.task(key).unwrap();
        task.fs.as_ref().map(|fs| fs.cwd.as_bytes().to_vec())
    };
    let parent_cwd = cwd(root_key);
    assert_eq!(
        parent_cwd,
        Some(b"/".to_vec()),
        "the parent's row has a cwd"
    );

    // Stage `call` through the production staging the child's owner runs.
    let stage = |call: HostFileCall| {
        let mut resolve = |_| {
            Some(NativeDescriptor::HostBacked {
                access: DescriptionAccess::ReadWrite,
            })
        };
        let mut releases = |_: &mut [carrick_core_abi::host_file::MapSourceReply]| 0;
        match crate::dispatch::stage_native_host_file(
            call,
            fixture.task,
            &ResidentUser,
            &mut NativeNamespace {
                table: [1, 1, 1],
                resolve: &mut resolve,
                releases: &mut releases,
            },
        ) {
            Some(HostFileStage::Request {
                record,
                output,
                resolves_path,
                map,
                chdir,
            }) => (record, output, resolves_path, map, chdir),
            other => panic!("{call:?} crosses to the carrier: {other:?}"),
        }
    };
    // Claim the published request's service ticket, as the carrier does.
    let claim = |record: RecordRef| {
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let identity = fixture.zone.record(record.id).identity();
        // SAFETY: the real native owner retains this exact control allocation.
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        let _queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap(),
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        // SAFETY: the service queue authenticates the notice and excludes
        // cancellation.
        unsafe { ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, identity) }
            .unwrap()
    };
    // Serve the claimed request as the carrier does: check it, write the
    // reply, acknowledge, and wake the child's service queue.
    let serve = |ticket: carrick_core_abi::service::ServiceTicket<&ServiceCell>,
                 check: &mut dyn FnMut(&HostFileRequestView<'_>),
                 result: i64,
                 reply: &[u8]| {
        let ServiceOperation::HostFile { payload, .. } = ticket.request().operation else {
            panic!("host file notice expected")
        };
        let record = ticket.request().identity.birth.record;
        // SAFETY: the ticket retains the request box; no ring execution can
        // mutate it.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                payload.ring_storage().raw() as *mut u8,
                payload.length().raw() as usize,
            )
        };
        let view = HostFileRequestView::parse(bytes).unwrap();
        check(&view);
        view.reply(result, reply).unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap(),
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        assert!(ticket.complete(true).is_ok());
        queue
            .notify_object(fixture.slot, &mut WakeEffects::default())
            .unwrap();
    };
    let access = |view: &HostFileRequestView<'_>| {
        let (context, path) = AccessContext::decode(view.input()).unwrap();
        (context.cwd.to_vec(), path.to_vec())
    };

    let (record, address, words) = capacity.select().unwrap();
    // SAFETY: the real fork publication retained this live child's record.
    let child_key = unsafe { fixture.runtime.record_binding(record) }
        .unwrap()
        .key;
    assert_ne!(child_key, root_key);
    assert_eq!(cwd(child_key), Some(b"/".to_vec()));
    let mut service = fixture.service();
    let mut child = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &words,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        child.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
    let fchdir = HostFileCall::decode(
        carrick_personality_linux::crossing::nr::FCHDIR,
        &[3, 0, 0, 0, 0, 0],
    )
    .expect("fchdir decodes to the native venue");
    let (staged, output, resolves_path, map, chdir) = stage(fchdir);
    assert!(chdir, "fchdir stages a chdir lookup");
    assert!(matches!(
        child.begin_host_file_service(
            staged,
            output,
            resolves_path,
            map,
            chdir,
            NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(50), counters)
        ),
        Ok(NativeResume::Left(None))
    ));
    assert!(child.take_handoff_receipt().is_some());
    drop(child);
    let ticket = claim(record);
    let mut stat = carrick_syscall_abi::LinuxStat::from_fields(
        &carrick_syscall_abi::LinuxPipeIdentity::new(1, 1).stat_fields(),
    );
    stat.st_mode = carrick_syscall_abi::LINUX_S_IFDIR | 0o755;
    let mut reply = zerocopy::IntoBytes::as_bytes(&stat).to_vec();
    reply.extend_from_slice(b"/tmp/a");
    serve(
        ticket,
        &mut |view| {
            assert_eq!(view.header().op, HostFileOp::Fchdir);
            assert_eq!(view.header().fd, 3);
            assert_eq!(access(view), (b"/".to_vec(), Vec::new()));
        },
        0,
        &reply,
    );
    // The child resumes through the host-file completion, whose chdir arm
    // is the runtime's one cwd writer.
    let (resumed, address, words) = capacity.select().unwrap();
    assert_eq!(resumed, record);
    let mut service = fixture.service();
    let mut child = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &words,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        child.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Returned(result)) if result.raw() == 0
    ));
    assert_eq!(cwd(root_key), parent_cwd, "the parent's cwd is its own");
    assert_eq!(cwd(child_key), Some(b"/tmp/a".to_vec()));

    // `mkdir("b")` in the child now resolves against its new cwd.
    let path = *b"b\0";
    let (staged, output, resolves_path, map, chdir) = stage(HostFileCall::Mkdirat {
        dirfd: -100,
        path: path.as_ptr() as u64,
        mode: 0o755,
    });
    assert!(matches!(
        child.begin_host_file_service(
            staged,
            output,
            resolves_path,
            map,
            chdir,
            NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(34), counters)
        ),
        Ok(NativeResume::Left(None))
    ));
    assert!(child.take_handoff_receipt().is_some());
    drop(child);
    let ticket = claim(record);
    serve(
        ticket,
        &mut |view| {
            assert_eq!(view.header().op, HostFileOp::Mkdirat);
            assert_eq!(access(view), (b"/tmp/a".to_vec(), b"b".to_vec()));
        },
        0,
        &[],
    );
    let (resumed, address, words) = capacity.select().unwrap();
    assert_eq!(resumed, record);
    let mut service = fixture.service();
    let mut child = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &words,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        child.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Returned(result)) if result.raw() == 0
    ));
    assert_eq!(cwd(child_key), Some(b"/tmp/a".to_vec()));
    assert_eq!(cwd(root_key), parent_cwd);
}

#[cfg(test)]
#[test]
fn native_parent_reaps_then_execs_a_child_after_slot_reuse() {
    parent_reaps_then_execs_child(false);
}

#[cfg(test)]
#[test]
fn native_namespace_mutation_baseline_exec_successor() {
    parent_reaps_then_execs_child(true);
}

#[cfg(test)]
fn parent_reaps_then_execs_child(namespace_census: bool) {
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
            child.resume_checkpoint(|_| Ok(None)),
            Ok(NativeResume::NoPending)
        ));
        assert!(matches!(
            child.begin_exec_service(
                test_exec_payload(b"/bin/static"),
                None,
                NativeServiceCall::new(
                    carrick_guest_arch::NativeOrdinal::new(221),
                    &carrick_el1_abi::Counters::new()
                )
            ),
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
        child.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
    assert_eq!(child.calling_tid(), child_pid);
    assert_eq!(
        fixture.task.mm.key.load(Ordering::Acquire),
        successor_mm.raw()
    );
    if namespace_census {
        // #1335 slice 1: successful exec changes the MM incarnation but cannot
        // manufacture a host task for a fork child. Drive the shared production
        // dispatcher before the shipping final-capture policy on that successor.
        // Physical performs this fixture's exec retirement and wake delivery
        // synchronously; acknowledge its host boundary before the next syscall.
        if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
            work.settled();
        }
        assert!(!child.is_root_process());
        let path = carrick_test_support::GuestUserBuffer::from_bytes(b"successor-name\0");
        let other = carrick_test_support::GuestUserBuffer::from_bytes(b"successor-target\0");
        let output = carrick_test_support::GuestUserBuffer::from_bytes(&[0u8; 128]);
        let counters = carrick_el1_abi::Counters::new();
        let names = carrick_el1_abi::InotifyNameCache::new();
        for (nr, args) in [
            (34, [(-100i64) as u64, path.arg(), 0o777, 0]),
            (35, [(-100i64) as u64, path.arg(), 0, 0]),
            (
                38,
                [(-100i64) as u64, path.arg(), (-100i64) as u64, other.arg()],
            ),
            (36, [other.arg(), (-100i64) as u64, path.arg(), 0]),
            (78, [(-100i64) as u64, path.arg(), output.arg(), 128]),
            (53, [(-100i64) as u64, path.arg(), 0o700, 0]),
        ] {
            let mut frame = carrick_el1_abi::TrapFrame {
                esr: 0x15 << 26,
                ..Default::default()
            };
            frame.x[8] = nr;
            frame.x[..4].copy_from_slice(&args);
            let route = crate::dispatch::dispatch_syscall_with_native::<
                _,
                crate::sched::FakeCpu,
                crate::sched::HardwareUserWord,
                _,
                ParkedContextWords,
            >(
                &mut frame,
                &counters,
                core::slice::from_ref(fixture.task),
                &[],
                &[],
                &[],
                &[],
                &names,
                None,
                None,
                None,
                Some(&mut *child),
                Some(source),
                None,
                |_| core::ptr::null_mut(),
            );
            if nr == 78 {
                // The exec successor uses the exact native file service;
                // native_exec_pipe_tests drives its reply and copyout too.
                assert_eq!(
                    route,
                    carrick_personality_linux::dispatch::CompletionRoute::NativeService
                );
                assert_eq!(counters.forwarded[78].load(Ordering::Relaxed), 0);
            } else {
                assert_eq!(
                    route,
                    carrick_personality_linux::dispatch::CompletionRoute::Forward
                );
                assert_eq!(
                    crate::dispatch::native_unstaged_exit(
                        &mut frame,
                        &fixture.task.linux,
                        carrick_el1_abi::Action::Forward,
                        || if child.is_root_process() {
                            NativeThreadGroupOwner::Root
                        } else {
                            NativeThreadGroupOwner::ForkChild
                        },
                        &counters,
                    ),
                    crate::dispatch::NativeUnstagedExit::Refused(carrick_el1_abi::Action::Served),
                );
                assert_eq!(frame.x[0] as i64, -38, "exec successor ordinal {nr}");
            }
            let refused = if nr == 78 { 0 } else { 1 };
            assert_eq!(
                counters.refused[nr as usize].load(Ordering::Relaxed),
                refused
            );
            assert_eq!(
                counters.refused_child[nr as usize].load(Ordering::Relaxed),
                refused
            );
            assert_eq!(
                counters.venue_refused[nr as usize].load(Ordering::Relaxed),
                0
            );
            assert_eq!(
                counters.venue_refused_child[nr as usize].load(Ordering::Relaxed),
                0
            );
            assert_eq!(counters.served[nr as usize].load(Ordering::Relaxed), 1);
            assert!(fixture.task.service_notice.take().unwrap().is_none());
        }
    }
    // The successor exits with status 7, which must wake the already-parked parent wait4 owner.
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
    match parent.resume_checkpoint(|_| Ok(None)) {
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
        reused.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
    assert!(matches!(
        reused.begin_exec_service(
            test_exec_payload(b"/bin/reused"),
            None,
            NativeServiceCall::new(
                carrick_guest_arch::NativeOrdinal::new(221),
                &carrick_el1_abi::Counters::new()
            )
        ),
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
            child.resume_checkpoint(|_| Ok(None)),
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
                    entry: OwnerEntry::Syscall,
                    demand: carrick_core_abi::service::CarrierDemand::Work,
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
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
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
        parent.resume_checkpoint(|_| Ok(None)),
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
        child.resume_checkpoint(|_| Ok(None)),
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
        parent.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::Returned(result)) if result.raw() == i64::from(child_pid)
    ));
    assert_eq!(parent_service.copies, vec![LinuxWaitStatus::exited(0)]);
}

#[cfg(test)]
#[test]
fn portal_wait_terminal_cancellation_resumes_exact_native_service_waiter() {
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
                        entry: OwnerEntry::Syscall,
                        demand: carrick_core_abi::service::CarrierDemand::Work,
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
        1,
        "an interrupt cannot cancel a committed CarrierWork wait",
    );
    assert!(
        matches!(
            fixture.zone.record(fixture.record.id).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ),
        "the committed service must not become runnable before terminal cancellation"
    );
    fixture
        .page
        .process_exit_custody()
        .publish_cancellation(carrick_core::terminal::ProcessCancellation::FatalSignal);
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
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(result) if result.raw() == 0x41),
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

/// #1974: in `NativeProcessEntry::enqueue_thread` (shared by x86 CPL0 and ARM),
/// `register_native_birth` commits the child into `resources.members` and drops
/// `graph.lock()` while the child's `ZoneRecord` is still `Claim::Free` with
/// `home() == None` (before `requeue_preempted` moves it to `Claim::Queued`).
/// With two live threads running in an x86 CPL0 process (`ParkedContextWords` +
/// `X86Mmu`), a sibling's `tgkill` during that window must hold the signal on
/// the registered-but-unqueued child and deliver it once at the child's first
/// entry (not dropped, not doubled), keep a blocked-at-clone mask pending
/// across first entry, and reject a freed record incarnation with `ESRCH`.
#[test]
#[cfg(test)]
fn x86_registered_claim_free_birth_before_requeue_sibling_tgkill() {
    use carrick_el1_abi::Lifecycle;
    use carrick_personality_linux::lifecycle::{ProcessNative, ThreadBirthAdmission};
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
    };
    use carrick_signal_core::policy::{SigBlockMask, Signal};
    use zerocopy::IntoBytes;

    let fixture = native_exec_fixture();
    fixture.install_handler(10, false);

    let controls = Box::leak(Box::new(core::array::from_fn::<_, 9, _>(|_| {
        ThreadControlSlot::new()
    })));
    fixture
        .runtime
        .admit_thread_stock(NativeLifecycleResources {
            page: fixture.page,
            controls,
        })
        .unwrap();

    let register_x86_claim_free_birth = |blocked: carrick_el1_abi::BlockedMask| {
        let leader_source = BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        };
        let mut leader_service = fixture.service();
        let leader_saved = words(fixture.address);
        let mut leader = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                leader_source,
                fixture.task,
                fixture.address,
                &leader_saved,
                &mut leader_service,
            )
            .unwrap();
        assert!(matches!(
            leader.prepare_thread_birth(),
            ThreadBirthAdmission::Ready
        ));
        let mut claimed = Some(fixture.page.claim_any().expect("x86 root stock entry"));
        let entry = claimed.as_ref().unwrap().entry();
        let identity = fixture.page.identity(entry).unwrap();
        let control_address = fixture.page.control_address(entry).unwrap();
        let child_slot = unsafe { &*(control_address as *const ThreadControlSlot) };
        assert!(child_slot.publish_visible_tid(identity.visible_tid));
        let record_id = fixture
            .zone
            .alloc_record(carrick_sched_core::ThreadIdentity {
                tid: u64::from(identity.tid),
                serial: identity.thread_serial,
                mm: fixture.address.mm.raw().get(),
                file_table: 5,
                generation: 0,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: core::ptr::from_ref(fixture.page).addr() as u64,
                control_slot: control_address,
            })
            .unwrap();
        let record = fixture.zone.record_ref(record_id);
        child_slot.reset_for_birth(blocked, 0, entry).unwrap();
        leader.bind_thread_birth(record, child_slot).unwrap();
        assert!(fixture.zone.issue_native_birth(record_id));
        leader
            .thread_spawned(41, identity.visible_tid, &mut || {
                Lifecycle::thread_born(fixture.page).ok_or(-11)?;
                fixture
                    .page
                    .record_born(
                        claimed.take().unwrap(),
                        carrick_el1_abi::BornRecord {
                            caller_task: 41,
                            caller_serial: 101,
                            clone_flags: 0x0035_0f00,
                            clear_child_tid: 0,
                            blocked,
                        },
                    )
                    .map_err(|_| -11)?;
                Ok(())
            })
            .unwrap();
        leader.lifecycle_admission_settled().unwrap();
        let process = fixture.runtime.graph.lock().root_key;
        assert!(
            !fixture
                .registry
                .register_native_birth(&fixture.runtime, process, leader_source, record)
                .unwrap()
        );
        assert_eq!(
            fixture.zone.record(record_id).claim(),
            carrick_sched_core::Claim::Free
        );
        assert_eq!(fixture.zone.record(record_id).home(), None);
        (record, identity.visible_tid, child_slot)
    };

    let deliver_x86_user_return =
        |slot: SlotId,
         record: RecordRef,
         control: &'static ThreadControlSlot,
         frame: &mut carrick_el1_abi::TrapFrame| {
            let identity = fixture.zone.record(record.id).identity();
            let child_task = Box::leak(Box::new(CurrentTask::new()));
            child_task.set(
                carrick_el1_abi::El1TaskId::from_linux_tid(identity.tid as i32),
                carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
                identity.file_table,
            );
            child_task
                .mm
                .key
                .store(fixture.address.mm.raw().get(), Ordering::Release);
            child_task
                .mm
                .thread_generation
                .store(identity.serial, Ordering::Release);
            child_task.publish_visible_pid(41);
            child_task.publish_lifecycle(identity.lifecycle_page, identity.control_slot);
            let mut child_service = fixture.service();
            let child_saved = words(fixture.address);
            let mut entry = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    BornInZoneSource {
                        zone: fixture.zone,
                        slot,
                    },
                    child_task,
                    fixture.address,
                    &child_saved,
                    &mut child_service,
                )
                .unwrap();
            let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
            let mut machine = HostArmSignalMachine {
                backend: HostArmBackend,
            };
            crate::signal_delivery::deliver_signal_on_syscall_return(
                child_task,
                control,
                &mut entry,
                frame,
                fp.as_bytes(),
                &mut machine,
            )
        };

    let sib_slot_id = SlotId::new(1);
    fixture.zone.drive(sib_slot_id, 1);
    fixture.zone.publish_slot(sib_slot_id, 1, Some(0), 1);
    fixture.zone.enter_guest(sib_slot_id);
    fixture
        .zone
        .install_space(sib_slot_id, fixture.address.mm.raw().get())
        .unwrap();
    let (sib_record, _, _) = register_x86_claim_free_birth(carrick_el1_abi::BlockedMask(0));
    assert!(
        fixture
            .zone
            .requeue_preempted(sib_slot_id, sib_record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(sib_slot_id).unwrap().record,
        sib_record.id
    );
    let sib_id = fixture.zone.record(sib_record.id).identity();
    let sib_task = Box::leak(Box::new(CurrentTask::new()));
    sib_task.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(sib_id.tid as i32),
        carrick_el1_abi::SnapshotGeneration::from_raw(sib_id.generation),
        sib_id.file_table,
    );
    sib_task
        .mm
        .key
        .store(fixture.address.mm.raw().get(), Ordering::Release);
    sib_task
        .mm
        .thread_generation
        .store(sib_id.serial, Ordering::Release);
    sib_task.publish_visible_pid(41);
    sib_task.publish_lifecycle(sib_id.lifecycle_page, sib_id.control_slot);
    assert_eq!(fixture.page.live(), 2);

    let child_slot_id = SlotId::new(2);
    fixture.zone.drive(child_slot_id, 1);
    fixture.zone.publish_slot(child_slot_id, 1, Some(0), 1);
    fixture.zone.enter_guest(child_slot_id);
    fixture
        .zone
        .install_space(child_slot_id, fixture.address.mm.raw().get())
        .unwrap();

    // Case A: unmasked at clone (`BlockedMask(0)`). Held while registered in
    // `Claim::Free`, delivered once at first entry, and not doubled.
    let (child_record, child_tid, child_control) =
        register_x86_claim_free_birth(carrick_el1_abi::BlockedMask(0));

    let mut sib_service = fixture.service();
    let sib_saved = words(fixture.address);
    let mut sender = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sib_slot_id,
            },
            sib_task,
            fixture.address,
            &sib_saved,
            &mut sib_service,
        )
        .unwrap();
    let sigusr1 = Signal::from_number(10).unwrap();
    assert_eq!(
        sender.tgkill(
            SignalThreadSelector::from_abi(41),
            SignalThreadSelector::from_abi(u64::from(child_tid)),
            SignalRequest::Deliver(sigusr1),
            SignalInfo::Generated(None),
        ),
        Ok(()),
        "x86 sibling tgkill during pre-requeue Claim::Free window must resolve"
    );
    drop(sender);

    let signals = fixture.runtime.current_signals(fixture.task).unwrap();
    assert!(
        signals
            .take_deliverable(fixture.record, SigBlockMask::NONE)
            .is_none(),
        "leader must not steal child's thread-directed signal"
    );
    assert!(
        signals
            .take_deliverable(sib_record, SigBlockMask::NONE)
            .is_none(),
        "sending sibling must not steal child's thread-directed signal"
    );

    assert!(
        fixture
            .zone
            .requeue_preempted(child_slot_id, child_record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(child_slot_id).unwrap().record,
        child_record.id
    );
    let mut first_frame = carrick_el1_abi::TrapFrame {
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        deliver_x86_user_return(child_slot_id, child_record, child_control, &mut first_frame),
        None,
        "handler setup completes in-place for user return"
    );
    assert_eq!(
        first_frame.elr, 0x7000,
        "first entry must redirect PC to installed SIGUSR1 handler"
    );
    assert_eq!(first_frame.x[0], 10);

    let mut second_frame = carrick_el1_abi::TrapFrame {
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        deliver_x86_user_return(
            child_slot_id,
            child_record,
            child_control,
            &mut second_frame
        ),
        None
    );
    assert_eq!(
        second_frame.elr, 0x40_0200,
        "SIGUSR1 must not deliver a second time"
    );

    // Negative control: once the record incarnation advances on retirement,
    // `signal_record_exists` must reject the stale `RecordRef`.
    let _ = fixture.zone.release_current(
        child_slot_id,
        child_record.id,
        &carrick_sched_core::ShortLockSpin,
    );
    fixture.zone.free_record(child_record.id);
    let mut sender = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sib_slot_id,
            },
            sib_task,
            fixture.address,
            &sib_saved,
            &mut sib_service,
        )
        .unwrap();
    assert_eq!(
        sender.tgkill(
            SignalThreadSelector::from_abi(41),
            SignalThreadSelector::from_abi(u64::from(child_tid)),
            SignalRequest::Probe,
            SignalInfo::Generated(None),
        ),
        Err(carrick_syscall_abi::LINUX_ESRCH),
        "freed record incarnation must never resolve as live"
    );
    drop(sender);

    // Case B: SIGUSR1 blocked in the inherited clone mask (`BlockedMask(1 << 9)`).
    // `tgkill` while registered-but-unqueued succeeds, first entry keeps PC at
    // `0x40_0200`, and SIGUSR1 stays pending until unmasked.
    let (masked_record, masked_tid, masked_control) =
        register_x86_claim_free_birth(carrick_el1_abi::BlockedMask(sigusr1.bit()));
    let mut sender = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sib_slot_id,
            },
            sib_task,
            fixture.address,
            &sib_saved,
            &mut sib_service,
        )
        .unwrap();
    assert_eq!(
        sender.tgkill(
            SignalThreadSelector::from_abi(41),
            SignalThreadSelector::from_abi(u64::from(masked_tid)),
            SignalRequest::Deliver(sigusr1),
            SignalInfo::Generated(None),
        ),
        Ok(()),
        "blocked-at-clone Claim::Free x86 birth must accept tgkill"
    );
    drop(sender);

    assert!(
        fixture
            .zone
            .requeue_preempted(child_slot_id, masked_record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(child_slot_id).unwrap().record,
        masked_record.id
    );
    let mut masked_frame = carrick_el1_abi::TrapFrame {
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        deliver_x86_user_return(
            child_slot_id,
            masked_record,
            masked_control,
            &mut masked_frame
        ),
        None
    );
    assert_eq!(
        masked_frame.elr, 0x40_0200,
        "blocked-at-clone SIGUSR1 must stay pending across x86 first entry"
    );

    masked_control.init_blocked(carrick_el1_abi::BlockedMask(0));
    assert_eq!(
        deliver_x86_user_return(
            child_slot_id,
            masked_record,
            masked_control,
            &mut masked_frame
        ),
        None
    );
    assert_eq!(
        masked_frame.elr, 0x7000,
        "unmasking must deliver the held SIGUSR1 once on x86"
    );
    let mut after_unmask = carrick_el1_abi::TrapFrame {
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        deliver_x86_user_return(
            child_slot_id,
            masked_record,
            masked_control,
            &mut after_unmask
        ),
        None
    );
    assert_eq!(after_unmask.elr, 0x40_0200);
}

#[test]
#[cfg(test)]
fn entropy_service_requires_retained_ring_payload_before_notice() {
    use carrick_core_abi::service::{ServiceOperation, entropy::EntropyPayloadDescriptor};
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
    let operation = ServiceOperation::Entropy {
        payload: EntropyPayloadDescriptor::checked(
            carrick_guest_arch::GuestVa::new(0x4000_0000),
            carrick_guest_arch::GuestLen::new(40),
        )
        .unwrap(),
    };
    assert!(matches!(
        entry.begin_service(operation, None),
        Err(NativeProcessError::Stale)
    ));
    assert_eq!(fixture.task.service_notice.take(), Ok(None));
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
            effect: None,
            data: service::CopyoutData::Bytes {
                address: UserVa::new(0x10000),
                bytes: bytes.clone(),
            },
            offset: 0,
            result: SyscallResult::new(37),
            prefix_on_fault: false,
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
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
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
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(result) if result.raw() == 37)
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
#[test]
fn poll_revents_crossing_a_page_retains_partial_copy_and_fault() {
    let fixture = native_exec_fixture();
    let mut service = fixture.service();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    for fault in [false, true] {
        service.child_copy_error = fault.then_some(NativeProcessError::Fault);
        service.child_copy_error_at = Some(0x11000);
        take_signal_copies();
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
        let output = service::OwnedCopyout {
            effect: None,
            data: service::CopyoutData::Poll(vec![carrick_syscall_abi::PollReventsOutput::new(
                carrick_guest_arch::GuestVa::new(0x10ff9),
                0x1234,
            )]),
            offset: 0,
            result: SyscallResult::new(1),
            prefix_on_fault: false,
        };
        let result = entry.finish_copyout(output);
        let bytes = 0x1234_i16.to_ne_bytes();
        if fault {
            assert!(matches!(result, Err(NativeProcessError::Fault)));
            assert_eq!(
                take_signal_copies(),
                [(UserVa::new(0x10fff), vec![bytes[0]])]
            );
        } else {
            assert!(matches!(result, Ok(NativeResume::Returned(value)) if value.raw() == 1));
            assert_eq!(
                take_signal_copies(),
                [
                    (UserVa::new(0x10fff), vec![bytes[0]]),
                    (UserVa::new(0x11000), vec![bytes[1]])
                ]
            );
        }
    }
}

#[cfg(test)]
fn retained_poll_output_owner_wait(
    cancel: bool,
    during_enrollment: bool,
    production_frame: bool,
    constructor: bool,
) {
    // Page-aligned guest user input lets the real TrapFrame path read its
    // pollfd array; physical output still goes through this fixture's native
    // service.
    let pages = production_frame.then(|| {
        carrick_test_support::GuestUserBuffer::zeroed(
            1024 * core::mem::size_of::<crate::file_table::PollFd>(),
        )
    });
    let address =
        pages.as_ref().map_or(0x10000, |pages| pages.arg()) + if constructor { 4092 } else { 0 };
    let piece = if constructor { 4 } else { 4096 };
    let expected_result = if constructor {
        0
    } else if production_frame {
        1024
    } else {
        37
    };
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    // The native fixture already owns process-lifetime leaked mappings.
    // This mapping must outlive its retained service rows too.
    let constructor_owner: Option<&'static std::sync::Arc<carrick_kernel::el1_ipc::HostIpc>> =
        constructor.then(|| {
            &*Box::leak(Box::new(std::sync::Arc::new(
                carrick_kernel::el1_ipc::HostIpc::new(1 << 20).unwrap(),
            )))
        });
    let constructor_table = constructor_owner.as_ref().map(|owner| {
        carrick_kernel::el1_ipc::HostTable::create(std::sync::Arc::clone(owner), 64, 8).unwrap()
    });
    let constructor_venue = constructor_owner
        .as_ref()
        .zip(constructor_table.as_ref())
        .map(|(owner, table)| {
            let map: &'static carrick_el1_abi::ipc_tables::IpcTableMap = unsafe {
                &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<
                    carrick_el1_abi::ipc_tables::IpcTableMap,
                >())
                .cast()
            };
            map.publish(
                fixture.task.linux.file_table.load(Ordering::Acquire),
                table.id().to_raw(),
            )
            .unwrap();
            let tables = Box::leak(Box::new(crate::ipc::MapTables(map)));
            crate::ipc::IpcVenue {
                region: owner.region(),
                tables,
            }
        });
    let mut service = fixture.service();
    if constructor {
        // This physical fixture models four-byte stores as registered words.
        // The eight-byte pipe output deliberately straddles two pages.
        for at in [address, address + piece] {
            service
                .tid_words
                .insert((fixture.address.mm.raw().get(), at), 0);
        }
    }
    let take_output = |service: &mut Physical<'_>| {
        if constructor {
            assert!(take_signal_copies().is_empty());
            core::mem::take(&mut service.tid_writes)
                .into_iter()
                .map(|(_, at, value)| (UserVa::new(at), value.to_ne_bytes().to_vec()))
                .collect::<Vec<_>>()
        } else {
            take_signal_copies()
        }
    };
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
    let output_address = if production_frame && !constructor {
        address + 6
    } else {
        address
    };
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
    service.child_copy_error_at = Some(if production_frame && !constructor {
        address + 14
    } else {
        address + piece
    });
    let bytes: Vec<u8> = if constructor {
        [0i32, 1i32]
            .into_iter()
            .flat_map(i32::to_ne_bytes)
            .collect()
    } else if production_frame {
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
    take_output(&mut service);
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
            frame.x[8] = if constructor {
                carrick_personality_linux::crossing::nr::PIPE2.raw()
            } else {
                carrick_syscall_abi::nr::PPOLL.raw()
            };
            frame.x[0] = address;
            frame.x[1] = if constructor {
                carrick_abi::LINUX_O_NONBLOCK | carrick_syscall_abi::LINUX_O_CLOEXEC
            } else {
                1024
            };
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
                constructor_venue.as_ref(),
                None,
                Some(&mut *entry),
                Some(source),
                None,
                |_| core::ptr::null_mut(),
            );
            assert_eq!(
                route,
                carrick_personality_linux::dispatch::CompletionRoute::Suspended,
                "result={}, address={address:#x}",
                frame.x[0] as i64
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
    if production_frame && !constructor {
        assert_eq!(
            take_output(&mut service),
            [(UserVa::new(address + 6), bytes[6..8].to_vec())]
        );
    } else {
        assert_eq!(
            take_output(&mut service),
            [(UserVa::new(address), bytes[..piece as usize].to_vec())]
        );
    }
    if let Some(table) = constructor_table.as_ref() {
        for fd in [0, 1] {
            assert_eq!(
                constructor_owner
                    .as_ref()
                    .unwrap()
                    .region()
                    .fd(carrick_kernel::el1_zone::HostLockWait)
                    .get(table.id(), carrick_el1_abi::ipc::fd::Fd(fd)),
                Err(carrick_el1_abi::ipc::fd::Error::BadFd)
            );
        }
    }
    if during_enrollment {
        assert!(take_output(&mut service).is_empty());
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
    let resumed = entry.resume_checkpoint(|_| Ok(None)).unwrap();
    drop(entry);
    if cancel {
        assert!(!matches!(resumed, NativeResume::Returned(_)));
        assert!(
            take_output(&mut service).is_empty(),
            "fatal cancellation cannot publish another output chunk"
        );
    } else {
        assert!(
            matches!(resumed, NativeResume::Returned(result) if result.raw() == expected_result)
        );
        if production_frame && !constructor {
            let expected: Vec<_> = (1..1024)
                .map(|index| {
                    let offset = index * 8 + 6;
                    (
                        UserVa::new(address + offset as u64),
                        bytes[offset..offset + 2].to_vec(),
                    )
                })
                .collect();
            assert_eq!(take_output(&mut service), expected);
        } else {
            assert_eq!(
                take_output(&mut service),
                [(
                    UserVa::new(address + piece),
                    bytes[piece as usize..].to_vec()
                )]
            );
        }
    }
    if let Some(table) = constructor_table.as_ref() {
        let region = constructor_owner.as_ref().unwrap().region();
        let authority = region.fd(carrick_kernel::el1_zone::HostLockWait);
        if cancel {
            let mut claims = authority.reserve_pair(table.id()).unwrap();
            assert_eq!(
                claims.fds(),
                Some([
                    carrick_el1_abi::ipc::fd::Fd(0),
                    carrick_el1_abi::ipc::fd::Fd(1)
                ])
            );
            authority.cancel_pair(&mut claims).unwrap();
            let object = region
                .create_pipe(65536, &carrick_kernel::el1_zone::HostLockWait)
                .unwrap();
            assert_eq!(
                object.to_raw().index,
                0,
                "cancel returns both endpoint references and the object"
            );
        } else {
            for fd in [0, 1] {
                assert_eq!(
                    authority.getfd(table.id(), carrick_el1_abi::ipc::fd::Fd(fd)),
                    Ok(true)
                );
            }
        }
    }
}

#[cfg(test)]
#[test]
fn completed_ppoll_output_retains_result_and_next_byte_across_owner_wait() {
    retained_poll_output_owner_wait(false, false, false, false);
}

#[cfg(test)]
#[test]
fn completed_ppoll_output_cancellation_commits_no_more_bytes() {
    retained_poll_output_owner_wait(true, false, false, false);
}

#[cfg(test)]
#[test]
fn completed_ppoll_output_cancellation_during_enrollment_never_returns_an_errno() {
    retained_poll_output_owner_wait(true, true, false, false);
}

#[cfg(test)]
#[test]
fn production_trap_frame_ppoll_retains_completed_output_across_owner_wait() {
    retained_poll_output_owner_wait(false, false, true, false);
}

#[cfg(test)]
#[test]
fn pipe_constructor_output_retains_both_claims_across_owner_wait() {
    retained_poll_output_owner_wait(false, false, true, true);
}
#[cfg(test)]
#[test]
fn pipe_constructor_output_cancellation_reclaims_both_claims_and_endpoints() {
    retained_poll_output_owner_wait(true, false, true, true);
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
        input_wait: None,
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
    retained_ipc_supply_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        supplied,
        already_ready,
        yielding,
        refusal,
    );
}

#[cfg(test)]
fn retained_ipc_supply_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
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
    let fixture = native_exec_fixture_for::<C, B>(make_words);
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
                &make_words(fixture.address),
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
            demand: carrick_core_abi::service::CarrierDemand::Work,
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
                entry.resume_checkpoint(|_| Ok(None)).unwrap(),
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
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
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
    let resumed = entry.resume_checkpoint(|_| Ok(None)).unwrap();
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
        let op = region.finish_operation(token, || {}).unwrap();
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
    retained_ipc_supply_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        false,
        false,
        false,
        AdapterRefusal::None,
    );
    retained_ipc_supply_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, false, false, false, AdapterRefusal::None);
}

#[cfg(test)]
fn retained_ipc_terminal_close_for<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    is_exec: bool,
) {
    use carrick_core_abi::service::ServiceOperation;
    use carrick_el1_abi::ipc::fd::{AccessMode, Description, Fd, StatusFlags};
    use carrick_el1_abi::ipc::{
        IpcBacking, IpcMmKey, IpcOpKind, IpcOperation, IpcTaskKey, IpcUserVa, OfdPin, WriteProgress,
    };

    let fixture = native_exec_fixture_for::<C, B>(make_words);
    let sibling = add_signal_sibling(&fixture, None, false);
    assert!(fixture.zone.mark_native_owned(sibling.record.id));

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
    let raw_pin = pin.into_raw();
    let sibling_binding = crate::common_entry::execution_binding(sibling.task);
    let raw_ipc_token = region
        .begin_operation(IpcOperation {
            kind: IpcOpKind::EventFdRead,
            pin: raw_pin,
            object: object.to_raw(),
            task: IpcTaskKey(sibling_binding.task.raw()),
            mm: IpcMmKey(sibling_binding.mm.raw()),
            buf: IpcUserVa(0x10000),
            progress: WriteProgress::new(8),
            ..IpcOperation::EMPTY
        })
        .unwrap();
    let token = carrick_el1::substrate::ipc::to_sched_token(raw_ipc_token).unwrap();
    let (token_index, token_generation) = (token.index(), token.generation());

    let sibling_source = BornInZoneSource {
        zone: fixture.zone,
        slot: sibling.slot,
    };
    let mut service = fixture.service();
    service.native_ipc = Some(region);
    {
        let mut sibling_entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                sibling_source,
                sibling.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            sibling_entry.yield_owned_operation(token),
            carrick_core::mm::transaction::OwnedOperationYield::Suspended
        ));
        // Close the numeric fd so only the retained IPC operation's pin keeps the object live.
        assert!(
            region
                .fd(carrick_sched_core::ShortLockSpin)
                .close(table, Fd(0))
                .unwrap()
                .is_none()
        );
        assert!(region.observe(object).is_ok());
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(sibling.slot, sibling.record.id)
            .is_queued()
    );
    fixture.zone.clear_current(sibling.slot);

    let leader_source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let successor_mm = if is_exec {
        {
            let mut leader = fixture
                .runtime
                .enter_registered(
                    fixture.registry,
                    leader_source,
                    fixture.task,
                    fixture.address,
                    &make_words(fixture.address),
                    &mut service,
                )
                .unwrap();
            assert!(matches!(
                leader.begin_exec_service(
                    test_exec_payload(b"/bin/static"),
                    None,
                    NativeServiceCall::new(
                        carrick_guest_arch::NativeOrdinal::new(221),
                        &carrick_el1_abi::Counters::new(),
                    ),
                ),
                Ok(NativeResume::Left(None))
            ));
            assert!(leader.take_handoff_receipt().is_some());
        }
        let successor_mm =
            publish_test_exec_reply(&fixture, fixture.control, fixture.slot, 0x1756, 0xa0_0000);
        let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
        assert_eq!(selected.record, fixture.record.id);
        // SAFETY: the production service completion selected this exact root record.
        let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
            .unwrap()
            .words;
        let mut leader = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                leader_source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            leader.resume_checkpoint(|_| Ok(None)),
            Ok(NativeResume::Left(None))
        ));
        assert!(leader.take_run_failure().is_none());
        Some(successor_mm)
    } else {
        let mut leader = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                leader_source,
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            leader.exit_group(23),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(leader.take_run_failure().is_none());
        assert!(leader.take_handoff_receipt().is_some());
        None
    };

    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(fixture.page),
        carrick_el1_abi::GateState::Closed
    );
    assert_eq!(
        fixture.zone.switch_in_full(sibling.slot).unwrap().record,
        sibling.record.id
    );
    {
        let mut sibling_entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                sibling_source,
                sibling.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(
            fixture
                .zone
                .record(sibling.record.id)
                .has_adapter_operation()
        );
        let result = sibling_entry.begin_service(
            ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
                demand: carrick_core_abi::service::CarrierDemand::Work,
            },
            None,
        );
        let settled = sibling_entry
            .settle_service_exit(result, NativeServiceExit::CarrierWork)
            .unwrap();
        assert!(matches!(settled, NativeResume::Left(None)));
    }
    fixture.zone.release_space(sibling.slot);

    assert!(
        !fixture
            .zone
            .record(sibling.record.id)
            .has_object_operation()
    );
    assert!(fixture.zone.live(sibling.record).is_none());
    let replay_ipc = carrick_el1::substrate::ipc::from_sched_token(
        carrick_sched_core::object_wait::OperationToken::new(token_index, token_generation)
            .unwrap(),
    )
    .unwrap();
    assert!(
        region.operation(&replay_ipc).is_err(),
        "the IPC operation record must be retired"
    );
    assert!(
        region.observe(object).is_err()
            && region
                .lock(object, &carrick_sched_core::ShortLockSpin)
                .is_err(),
        "retirement must release the final endpoint pin"
    );
    assert!(
        region
            .fd(carrick_sched_core::ShortLockSpin)
            .unpin_filtered(
                OfdPin::from_raw(raw_pin),
                crate::ipc::is_zone_releasable_backing,
            )
            .is_err(),
        "a second unpin of the retired pin must fail"
    );
    let replay_token =
        carrick_sched_core::object_wait::OperationToken::new(token_index, token_generation)
            .unwrap();
    assert!(
        matches!(
            crate::ipc::retire_native_operation(
                &region,
                fixture.zone,
                sibling.slot,
                sibling.task,
                sibling_binding,
                replay_token,
            ),
            Err(NativeProcessError::Stale)
        ),
        "a second retirement of the same token must return Stale"
    );

    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    // SAFETY: the sibling's terminal notification woke this exact closing owner.
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            leader_source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let completed = leader.resume_checkpoint(|_| Ok(None)).unwrap();
    if let Some(successor_mm) = successor_mm {
        assert!(matches!(completed, NativeResume::NoPending));
        assert_eq!(
            fixture.zone.installed_space(fixture.slot),
            successor_mm.raw()
        );
    } else {
        assert!(matches!(
            completed,
            NativeResume::Left(Some(status)) if status == LinuxWaitStatus::exited(23)
        ));
    }
}

#[cfg(test)]
#[test]
fn exec_settlement_retires_retained_ipc_operation_and_pin_once() {
    retained_ipc_terminal_close_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words, true,
    );
    retained_ipc_terminal_close_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, true);
}

#[cfg(test)]
#[test]
fn exit_group_settlement_retires_retained_ipc_operation_and_pin_once() {
    retained_ipc_terminal_close_for::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words, false,
    );
    retained_ipc_terminal_close_for::<
        carrick_el1_abi::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words, false);
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

/// #1467: under fork/exit churn a host requester (control wake, settlement,
/// wait service) may claim a running native child (OnCpu -> OnCpuRequested)
/// while that child enters a service park, with its parent alive and parked.
/// Park admission refusing for that request is contention: the child must
/// leave through its owner checkpoint with its exact operation retained, never
/// quarantine the carrier. Busy once, then success: after the host releases the
/// child, its next owner entry reparks and the ticket completes it.
#[cfg(test)]
#[test]
fn host_request_during_service_park_yields_then_reparks() {
    host_contended_service_park(
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Syscall,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        false,
    );
}

/// #1467 review P0: the requester that closed the park takes the yielded
/// record from the run queue before the yield's receipt is constructed. That
/// takeover is the request being honoured, so the receipt still stands and the
/// exact operation reruns after the handback; it must never quarantine.
#[cfg(test)]
#[test]
fn host_takeover_before_yield_receipt_is_not_now() {
    host_contended_service_park(
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            entry: OwnerEntry::Syscall,
            demand: carrick_core_abi::service::CarrierDemand::Work,
        },
        true,
    );
}

/// #1467 review P1: a contended exception service yields through the
/// exception owner checkpoint, so its next owner entry re-delivers the
/// exception instead of re-executing a syscall at that PC. The parent stays
/// parked in `wait4` while its child takes the Busy-once refusal; after the
/// handback the refused exception completes through `resume_checkpoint` as
/// the exception's own signal, never as a syscall return or SVC retry.
#[cfg(test)]
#[test]
fn host_request_during_exception_service_park_yields_as_exception() {
    host_contended_service_park(
        carrick_core_abi::service::ServiceOperation::Exception(
            carrick_core_abi::service::NativeException {
                kind: carrick_core_abi::service::NativeExceptionKind::UndefinedInstruction,
                address: UserVa::new(0x4000),
            },
        ),
        false,
    );
}

/// #1467 review P1, fault arm: a contended fault service yields as an
/// exception and, once supplied, resumes by re-executing the faulting
/// instruction, not by returning from or retrying a syscall.
#[cfg(test)]
#[test]
fn host_request_during_fault_service_park_yields_as_exception() {
    host_contended_service_park(
        carrick_core_abi::service::ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
            address: UserVa::new(0x4000),
            access: carrick_guest_arch::Access::Read,
            present: true,
        }),
        false,
    );
}

#[cfg(test)]
fn host_contended_service_park(
    operation: carrick_core_abi::service::ServiceOperation,
    takeover_before_receipt: bool,
) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_sched_core::object_wait::{ObjectWaitKey, OwnerEntry, ResumeDisposition};
    use carrick_sched_core::{Claim, Handback, HostClaim, ShortLockSpin};

    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let (record, address, words) = capacity.select().unwrap();
    let identity = fixture.zone.record(record.id).identity();
    // A second live process: the root task is alive and not the child.
    assert_ne!(record.id, fixture.record.id);
    assert_eq!(
        fixture
            .zone
            .claim_for_host(record, None, Handback::Control, &ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            }),
        HostClaim::El1Held { slot: fixture.slot }
    );
    let mut service = fixture.service();
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &words,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::NoPending
    ));
    if takeover_before_receipt {
        let (zone, slot) = (fixture.zone, fixture.slot);
        fixture
            .runtime
            .install_yield_receipt_race_hook(alloc::boxed::Box::new(move || {
                assert!(matches!(
                    zone.record(record.id).claim(),
                    Claim::Queued { .. }
                ));
                // The stopped executor honours the request from its run queue
                // (`el1_zone::hand_back_wanted`) before the receipt exists.
                let mut wanted = alloc::vec::Vec::new();
                assert_eq!(
                    zone.take_host_wanted(slot, &mut |wanted_record| wanted.push(wanted_record)),
                    1
                );
                assert_eq!(wanted.as_slice(), &[record]);
            }));
    }
    let expected_entry = match operation {
        ServiceOperation::Exception(_) | ServiceOperation::Fault(_) => OwnerEntry::Exception,
        _ => OwnerEntry::Syscall,
    };
    let parked = entry.begin_service(operation, None);
    assert!(
        matches!(parked, Ok(NativeResume::Left(None))),
        "host request during service park must yield, not quarantine: {:?}",
        parked.as_ref().err()
    );
    assert!(entry.take_handoff_receipt().is_some());
    drop(entry);
    drop(service);
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    // The request was published before the park; the yield keeps it.
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    assert_eq!(
        fixture.zone.record(record.id).resume_disposition(),
        ResumeDisposition::OwnerContinuation(expected_entry),
        "the yield must resume through the operation's own owner entry"
    );
    // Neither retained owner has a host completion yet. The ring checkpoint
    // consumes it before an exception PC or a syscall result can be handed back.
    assert!(fixture.zone.record(record.id).requires_native_entry());
    if takeover_before_receipt {
        assert!(matches!(
            fixture.zone.record(record.id).claim(),
            Claim::Host { .. }
        ));
    } else {
        assert!(matches!(
            fixture.zone.record(record.id).claim(),
            Claim::Queued { .. }
        ));
    }
    assert!(fixture.zone.record(record.id).has_object_operation());
    assert!(fixture.runtime.graph.lock().has_member_wait(&record));
    // SAFETY: the real native owner retains this exact control allocation.
    let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    let ticket =
        unsafe { ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, identity) }
            .unwrap();
    // The yield retained this exact operation: the record's token names this
    // record and the claimed request's sequence, and the request is unchanged.
    assert_eq!(ticket.request().operation, operation);
    let census = fixture.zone.record(record.id).object_wait_census().unwrap();
    assert_eq!(
        (census.operation, census.operation_generation),
        (
            u64::from(record.id.raw()),
            ticket.request().identity.sequence.get()
        ),
        "the yield must retain the exact service operation"
    );

    // The stopped executor honours the request (`el1_zone::hand_back_wanted`),
    // and the native handback places the exact record back on a slot.
    if !takeover_before_receipt {
        assert!(!fixture.zone.record(record.id).needs_host());
    }
    if !takeover_before_receipt {
        let mut wanted = alloc::vec::Vec::new();
        assert_eq!(
            fixture
                .zone
                .take_host_wanted(fixture.slot, &mut |wanted_record| wanted
                    .push(wanted_record)),
            1
        );
        assert_eq!(wanted.as_slice(), &[record]);
    }
    assert!(fixture.zone.place_native_handback(record).is_some());
    assert!(!fixture.zone.record(record.id).needs_host());

    // Its next owner entry reparks the same exact request.
    let reenter = |expect_left: bool| {
        let (again, address, words) = capacity.select().unwrap();
        assert_eq!(again, record);
        assert_eq!(
            fixture.zone.record(record.id).resume_disposition(),
            ResumeDisposition::OwnerContinuation(expected_entry),
            "the selected record must enter through the operation's own owner entry"
        );
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                address,
                &words,
                &mut service,
            )
            .unwrap();
        let resumed = entry.resume_checkpoint(|_| Ok(None));
        if expect_left {
            assert!(matches!(resumed, Ok(NativeResume::Left(None))));
            drop(entry);
            assert!(fixture.zone.slot(fixture.slot).current().is_none());
            assert!(matches!(
                fixture.zone.record(record.id).claim(),
                Claim::Parked { .. }
            ));
        } else {
            let observed = match &resumed {
                Ok(NativeResume::NoPending) => "NoPending",
                Ok(NativeResume::RetrySavedSyscall) => "RetrySavedSyscall",
                Ok(NativeResume::RetrySyscall) => "RetrySyscall",
                Ok(NativeResume::Returned(_)) => "Returned",
                Ok(NativeResume::Left(_)) => "Left",
                Ok(NativeResume::Invalid) => "Invalid",
                Err(_) => "Err",
            };
            if expected_entry == OwnerEntry::Exception {
                // An exception owner resumes at its faulting instruction (or
                // the signal it raised), never through syscall handling: no
                // return value, no SVC retry.
                assert!(
                    matches!(resumed, Ok(NativeResume::NoPending)),
                    "a completed exception service resumed as {observed}"
                );
            } else {
                assert!(
                    matches!(resumed, Ok(NativeResume::Returned(_))),
                    "{observed}"
                );
            }
            drop(entry);
            assert_eq!(
                fixture.zone.record(record.id).resume_disposition(),
                ResumeDisposition::UserReturn,
                "completion must consume the owner continuation"
            );
        }
    };
    reenter(true);
    let queue = fixture
        .zone
        .object_wait(
            ObjectWaitKey::native_service(record).unwrap(),
            &ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    assert_eq!(queue.native_service_member(record), Some(identity));
    drop(queue);
    assert!(fixture.task.service_notice.take().unwrap().is_none());
    // A refused exception raises its signal; a supplied fault or syscall
    // service completes normally.
    let refused_exception = matches!(operation, ServiceOperation::Exception(_));
    ticket
        .complete(!refused_exception)
        .unwrap_or_else(|_| panic!("yielded service ticket was cancelled"));
    fixture
        .zone
        .object_wait(
            ObjectWaitKey::native_service(record).unwrap(),
            &ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap()
        .notify_object(fixture.slot, &mut Default::default())
        .unwrap();
    reenter(false);
    if expected_entry == OwnerEntry::Exception {
        let key = fixture
            .registry
            .state
            .lock()
            .members
            .values()
            .find(|member| member.record == record)
            .unwrap()
            .process;
        let pending = fixture
            .runtime
            .graph
            .lock()
            .owner
            .task(key)
            .unwrap()
            .native()
            .resources()
            .signals()
            .pending_set(record);
        // The exception's own completion: SIGILL for the refused undefined
        // instruction, nothing for a supplied fault that simply retries.
        assert_eq!(
            pending.contains(carrick_signal_core::policy::Signal::ILL),
            refused_exception
        );
    }
}

/// #1467, owner-wait arm: a portal owner wait refused by a host request keeps
/// its exact operation and leaves through the owner checkpoint instead of
/// quarantining; the honoured request returns it to its slot to repark.
#[cfg(test)]
#[test]
fn host_request_during_owner_wait_park_yields_then_reparks() {
    use carrick_sched_core::{Claim, Handback, HostClaim, ShortLockSpin};
    let fixture = native_exec_fixture();
    let mut service = fixture.service();
    let handle = service.service_mm_handle(&fixture.address).unwrap();
    let space = fixture
        .zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .unwrap();
    space
        .admit_notifications(handle.incarnation(), &ShortLockSpin, &|effects| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        })
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
    let birth = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
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
    assert_eq!(
        fixture.zone.claim_for_host(
            fixture.record,
            None,
            Handback::Control,
            &ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        ),
        HostClaim::El1Held { slot: fixture.slot }
    );
    let saved = words(fixture.address);
    {
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
        let parked = entry.begin_owner_service_wait(
            carrick_core_abi::service::ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
                demand: carrick_core_abi::service::CarrierDemand::Work,
            },
            wait,
        );
        assert!(
            matches!(parked, Ok(NativeResume::Left(None))),
            "host request during owner wait must yield, not quarantine: {:?}",
            parked.as_ref().err()
        );
        assert!(entry.take_handoff_receipt().is_some());
    }
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert!(matches!(
        fixture.zone.record(fixture.record.id).claim(),
        Claim::Queued { .. }
    ));
    assert!(
        fixture
            .zone
            .record(fixture.record.id)
            .has_object_operation()
    );
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&fixture.record)
    );
    let mut wanted = alloc::vec::Vec::new();
    assert_eq!(
        fixture
            .zone
            .take_host_wanted(fixture.slot, &mut |record| wanted.push(record)),
        1
    );
    assert_eq!(wanted.as_slice(), &[fixture.record]);
    assert!(fixture.zone.place_native_handback(fixture.record).is_some());
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    {
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
        // As for a parked owner wait the host claimed: the owner wait's
        // next entry finishes it and re-evaluates the waiting operation.
        assert!(matches!(
            entry.resume_checkpoint(|_| Ok(None)),
            Ok(NativeResume::Returned(_))
        ));
    }
    assert!(
        !fixture
            .runtime
            .graph
            .lock()
            .has_member_wait(&fixture.record)
    );
}

/// Production signal setup retains the pre-change mask while its output waits.
#[cfg(test)]
#[test]
fn sigprocmask_oldset_owner_wait_commits_mask_and_output_once() {
    signal_setup_output_owner_wait(false);
}

#[cfg(test)]
#[test]
fn native_signal_setup_cross_page_owner_wait_writes_each_byte_once() {
    signal_setup_output_owner_wait(true);
}

#[cfg(test)]
fn signal_setup_output_owner_wait(cross_page: bool) {
    use carrick_personality_linux::dispatch::SyscallFrame;
    struct Frame {
        inner: carrick_el1_abi::TrapFrame,
        native: bool,
    }
    impl SyscallFrame for Frame {
        fn canonical_ordinal(&self) -> carrick_syscall_abi::CanonicalNr {
            self.inner.canonical_ordinal()
        }
        fn argument(&self, index: usize) -> Option<u64> {
            self.inner.argument(index)
        }
        fn result(&self) -> carrick_guest_arch::NativeReturnWord {
            self.inner.result()
        }
        fn set_result(&mut self, result: carrick_guest_arch::NativeReturnWord) {
            self.inner.set_result(result);
        }
        fn slot(&self) -> Option<carrick_guest_arch::SlotId> {
            self.inner.slot()
        }
        fn user_sp(&self) -> Option<UserVa> {
            self.inner.user_sp()
        }
    }
    impl crate::dispatch::GuestDispatchFrame for Frame {
        fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
            carrick_guest_arch::NativeOrdinal::new(if self.native { 14 } else { 135 })
        }
        fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
            if self.native {
                carrick_personality_linux::crossing::HostCrossingSet::X86
            } else {
                carrick_personality_linux::crossing::HostCrossingSet::Aarch64
            }
        }
        fn arm_frame(&mut self) -> Option<&mut carrick_el1_abi::TrapFrame> {
            if self.native {
                None
            } else {
                Some(&mut self.inner)
            }
        }
        fn arm_frame_ref(&self) -> Option<&carrick_el1_abi::TrapFrame> {
            if self.native { None } else { Some(&self.inner) }
        }
        fn arm_scheduler(&self) -> bool {
            !self.native
        }
        fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
            None
        }
    }
    use crate::thread_setup::{LifecycleThread, LifecycleVenue};
    struct Venue {
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
    }
    impl LifecycleVenue for Venue {
        fn thread<'a>(&'a self, _: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
            Some(LifecycleThread {
                page: self.page,
                slot: self.control,
            })
        }
        fn born_slot(&self, _: &ThreadLifecyclePage, _: EntryRef) -> Option<&ThreadControlSlot> {
            None
        }
    }
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let venue = Venue {
        page: fixture.page,
        control: fixture.control,
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
    if !cross_page {
        access.raise(space.index());
    }
    // SAFETY: the fixture retains this exact owner's live Gate observation.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    service.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
    let set = carrick_test_support::GuestUserBuffer::from_value(u64::MAX);
    let old = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let old_address = old.arg() + if cross_page { 4093 } else { 0 };
    if cross_page {
        service.child_copy_error_at = Some(old_address + 3);
        service.on_copy_complete = Some(Box::new(move |address| {
            if address.raw() == old_address {
                access.raise(space.index());
            }
        }));
    }
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
        let mut frame = Frame {
            inner: carrick_el1_abi::TrapFrame::default(),
            native: cross_page,
        };
        frame.inner.x[8] = 135;
        frame.inner.x[..4].copy_from_slice(&[0, set.arg(), old_address, 8]);
        crate::file::SIMULATE_COPYOUT_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &carrick_el1_abi::Counters::new(),
            core::slice::from_ref(fixture.task),
            &[],
            &[],
            &[],
            &[],
            &carrick_el1_abi::InotifyNameCache::new(),
            None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None,
            Some(&venue),
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        crate::file::SIMULATE_COPYOUT_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
        assert_eq!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::Suspended
        );
    }
    assert_eq!(fixture.control.blocked().0, !0x0004_0100_u64);
    assert_eq!(
        take_signal_copies(),
        if cross_page {
            vec![(UserVa::new(old_address), vec![0; 3])]
        } else {
            vec![]
        }
    );
    // Detect any replay of the already committed mask operation on resume.
    let _ = fixture.control.store_blocked_then_read_pending(
        carrick_el1_abi::BlockedMask(0x80),
        fixture.control.pending(),
    );
    service.child_copy_error = None;
    access.lower(space.index());
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
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(result) if result.raw() == 0)
    );
    assert_eq!(fixture.control.blocked().0, 0x80);
    assert_eq!(
        take_signal_copies(),
        if cross_page {
            vec![(UserVa::new(old_address + 3), vec![0; 5])]
        } else {
            vec![(UserVa::new(old_address), 0_u64.to_le_bytes().to_vec())]
        }
    );
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::NoPending
    ));
    assert!(take_signal_copies().is_empty());
}

#[cfg(test)]
#[test]
fn rehomed_signal_copy_service_keeps_native_intake_custody() {
    rehomed_signal_copy_service(false);
}

#[cfg(test)]
#[test]
fn rehomed_signal_input_service_returns_original_syscall_to_host() {
    rehomed_signal_copy_service(true);
}

#[cfg(test)]
fn rehomed_signal_copy_service(input: bool) {
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let identity = fixture.zone.record(fixture.record.id).identity();
    // A prior completed in-ring operation leaves the same live member's
    // service cell idle but bound to its previous scheduler record.
    let process = fixture.runtime.graph.lock().root_key;
    let handle = fixture
        .service()
        .service_mm_handle(&fixture.address)
        .unwrap();
    service::bind_member_service(
        fixture.zone,
        process,
        carrick_core_abi::service::ServiceOrigin::Initial,
        fixture.record,
        carrick_core_abi::EntryThreadGeneration::from_raw(identity.serial),
        fixture.control,
        handle,
    )
    .unwrap();
    // A completed host-boundary call discards its unpublished home. The next
    // SVC allocates and rehomes the same live thread onto another incarnation.
    fixture
        .zone
        .discard_unpublished(fixture.slot, fixture.record.id);
    let record = fixture.zone.current_or_new(fixture.slot, identity).unwrap();
    let reference = fixture.zone.record_ref(record);
    assert_ne!(reference, fixture.record);
    assert!(!fixture.zone.record(record).is_native_owned());
    // SAFETY: this test owns the unpublished home and its saved context.
    unsafe {
        *fixture.zone.record(record).ctx_mut() = words(fixture.address);
    }
    fixture.control.bind_zone_record(reference);
    fixture
        .registry
        .rehome_entry(
            source,
            fixture.task,
            fixture.address,
            fixture.page,
            fixture.control,
        )
        .unwrap()
        .unwrap();
    let mut service = fixture.service();
    if input {
        service.prepare_copy_error = Some(NativeProcessError::Busy);
    } else {
        service.child_copy_error = Some(NativeProcessError::Busy);
    }
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
    let outcome = if input {
        let mut observed = Vec::new();
        let outcome = entry.wait_guest_copy_observed(
            carrick_core::user_copy::GuestCopyRequest {
                address: UserVa::new(0x10000),
                len: carrick_guest_arch::GuestLen::new(8),
                access: carrick_guest_arch::Access::Read,
            },
            &mut |reason| observed.push(reason),
        );
        assert_eq!(
            observed,
            vec![carrick_personality_linux::lifecycle::InputPreparationRefusal::OwnerBusy]
        );
        outcome
    } else {
        entry.complete_copyout(
            UserVa::new(0x10000),
            0_u64.to_le_bytes().to_vec(),
            SyscallResult::new(0),
        )
    };
    assert!(matches!(
        outcome,
        LifecycleOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            ..
        }
    ));
    assert!(entry.take_handoff_receipt().is_some());
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    assert_eq!(notice.record, reference);
    assert!(
        !fixture.zone.record(record).is_native_owned(),
        "a temporary ring continuation must preserve the host execution owner"
    );
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(reference).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    assert_eq!(
        queue.native_service_member(reference),
        Some(identity),
        "the exact service intake must retain its native member after host-record rehome"
    );
    // SAFETY: the fixture retains this exact record and authenticates its
    // notice while holding the same service queue as production intake.
    let ticket = unsafe {
        carrick_core_abi::service::ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            identity,
        )
    }
    .unwrap();
    drop(queue);
    drop(entry);
    service.child_copy_error = None;
    service.prepare_copy_error = None;
    take_signal_copies();
    ticket
        .complete(true)
        .unwrap_or_else(|_| panic!("copy service ticket was cancelled"));
    fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(reference).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap()
        .notify_object(fixture.slot, &mut Default::default())
        .unwrap();
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        record
    );
    let saved = unsafe { fixture.runtime.record_binding(reference) }
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
        matches!(
            entry.resume_checkpoint(|_| Ok(None)),
            Ok(NativeResume::Left(None))
        ),
        "a host-owned member must return its completed context to its host executor"
    );
    assert!(!fixture.zone.record(record).is_native_owned());
    assert_eq!(
        fixture.zone.record(record).resume_disposition(),
        carrick_sched_core::object_wait::ResumeDisposition::UserReturn
    );
    let mut expected = saved;
    if input {
        expected.restart_syscall();
        assert!(take_signal_copies().is_empty());
    } else {
        expected.set_syscall_return(0);
        assert_eq!(
            take_signal_copies(),
            [(UserVa::new(0x10000), 0_u64.to_le_bytes().to_vec())]
        );
    }
    // Every saved word is checked: retry preserves arguments; completion
    // changes only the syscall result. The host receives this exact context.
    let actual = unsafe { *fixture.zone.record(record).ctx_mut() };
    assert_eq!(actual, expected);
    assert!(fixture.zone.record(record).needs_host());
}

#[cfg(test)]
#[test]
fn sigprocmask_set_owner_wait_redispatches_before_effects() {
    use crate::thread_setup::{LifecycleThread, LifecycleVenue};
    struct Venue {
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
    }
    impl LifecycleVenue for Venue {
        fn thread<'a>(&'a self, _: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
            Some(LifecycleThread {
                page: self.page,
                slot: self.control,
            })
        }
        fn born_slot(&self, _: &ThreadLifecyclePage, _: EntryRef) -> Option<&ThreadControlSlot> {
            None
        }
    }
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let venue = Venue {
        page: fixture.page,
        control: fixture.control,
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
    access.raise(space.index());
    // SAFETY: the fixture retains this exact owner's live Gate observation.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    service.prepare_copy_error = Some(NativeProcessError::OwnerWait(wait));
    let set = carrick_test_support::GuestUserBuffer::from_value(u64::MAX);
    let old = carrick_test_support::GuestUserBuffer::from_value(0xdead_beef_u64);
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
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 135;
        frame.x[..4].copy_from_slice(&[0, set.arg(), old.arg(), 8]);
        crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
        let route = crate::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &carrick_el1_abi::Counters::new(),
            core::slice::from_ref(fixture.task),
            &[],
            &[],
            &[],
            &[],
            &carrick_el1_abi::InotifyNameCache::new(),
            None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
            None,
            Some(&venue),
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
        assert_eq!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::Suspended
        );
    }
    assert_eq!(fixture.control.blocked().0, 0);
    assert_eq!(old.get::<u64>(0), 0xdead_beef);
    assert!(take_signal_copies().is_empty());
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
            .is_some(),
        "a handled signal cannot cancel input preparation"
    );
    service.prepare_copy_error = None;
    access.lower(space.index());
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
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::RetrySyscall
    ));
    assert_eq!(fixture.control.blocked().0, 0);
    assert!(take_signal_copies().is_empty());
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 135;
    frame.x[..4].copy_from_slice(&[0, set.arg(), old.arg(), 8]);
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &carrick_el1_abi::Counters::new(),
        core::slice::from_ref(fixture.task),
        &[],
        &[],
        &[],
        &[],
        &carrick_el1_abi::InotifyNameCache::new(),
        None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        None,
        Some(&venue),
        Some(&mut *entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork
    );
    assert_eq!(frame.x[0], 0);
    assert_eq!(fixture.control.blocked().0, !0x0004_0100_u64);
    assert_eq!(old.read::<u64>(0), 0);
    assert!(take_signal_copies().is_empty());
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::NoPending
    ));
    assert!(take_signal_copies().is_empty());
}

/// Production service admission owns the allocation until the exact ACK;
/// deterministic bytes isolate transport custody from the carrier RNG.
#[test]
#[cfg(test)]
fn entropy_service_retains_reply_through_busy_and_resume() {
    entropy_service_retained_cursor(false);
}

#[test]
#[cfg(test)]
fn entropy_service_retains_reply_through_owner_wait_and_resume() {
    entropy_service_retained_cursor(true);
}

#[cfg(test)]
fn entropy_service_retained_cursor(owner_wait: bool) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation, entropy};
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
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
        assert!(matches!(
            entry.begin_entropy_service(
                UserVa::new(0x10ff8),
                16,
                NativeEntropyFlags::from_bits_retain(1),
                carrick_guest_arch::GuestLen::new(16)
            ),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // SAFETY: the fixture owns the exact member and holds its service queue.
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(fixture.record.id).identity(),
        )
    }
    .unwrap();
    let ServiceOperation::Entropy { payload } = ticket.request().operation else {
        panic!("expected entropy");
    };
    // SAFETY: the pending service owns this allocation until ticket settlement;
    // the selected member is parked and cannot access it while claimed.
    let record = unsafe {
        core::slice::from_raw_parts_mut(
            payload.address().raw() as *mut u8,
            payload.length().raw() as usize,
        )
    };
    assert_eq!(entropy::request(record).unwrap().flags, 1);
    record[entropy::ENTROPY_HEADER_BYTES..].copy_from_slice(&[0x73; 16]);
    entropy::publish_reply(record, 16).unwrap();
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    let gate = if owner_wait {
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
        access.raise(space.index());
        // SAFETY: fixture retains the exact live Gate observation and owner.
        let wait = unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                handle,
                carrick_core_abi::PortalWaitCause::Gate,
                observed.revision(),
            )
        };
        Some((access, space.index(), wait))
    } else {
        None
    };
    service.child_copy_error = Some(
        gate.as_ref()
            .map_or(NativeProcessError::Busy, |(_, _, wait)| {
                NativeProcessError::OwnerWait(*wait)
            }),
    );
    service.child_copy_error_at = Some(0x11000);
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
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::Left(None)
        ));
    }
    assert_eq!(
        take_signal_copies(),
        [(UserVa::new(0x10ff8), vec![0x73; 8])]
    );
    if let Some((access, index, _)) = gate {
        assert!(fixture.task.service_notice.take().unwrap().is_none());
        service.child_copy_error = None;
        access.lower(index);
    } else {
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record)
                    .unwrap(),
                &carrick_sched_core::ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        // SAFETY: exact member service queue is held, as above.
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
    }
    service.child_copy_error = None;
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
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(value) if value.raw() == 16)
    );
    assert_eq!(
        take_signal_copies(),
        [(UserVa::new(0x11000), vec![0x73; 8])]
    );
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum EntropyReplyCase {
    FirstFault,
    Prefix,
    InvalidFlags,
    CancelBeforeReply,
    CancelAfterReply,
}

#[test]
#[cfg(test)]
fn entropy_service_first_byte_fault_returns_efault() {
    entropy_service_result(EntropyReplyCase::FirstFault);
}
#[test]
#[cfg(test)]
fn entropy_service_accessible_prefix_is_a_short_read() {
    entropy_service_result(EntropyReplyCase::Prefix);
}
#[test]
#[cfg(test)]
fn entropy_service_flags_precede_output_fault() {
    entropy_service_result(EntropyReplyCase::InvalidFlags);
}
#[test]
#[cfg(test)]
fn entropy_service_cancellation_before_reply_releases_payload() {
    entropy_service_result(EntropyReplyCase::CancelBeforeReply);
}
#[test]
#[cfg(test)]
fn entropy_service_cancellation_after_reply_keeps_generated_bytes() {
    entropy_service_result(EntropyReplyCase::CancelAfterReply);
}

#[cfg(test)]
std::thread_local! {
    static ENTROPY_WRITABLE_END: core::cell::Cell<Option<UserVa>> = const { core::cell::Cell::new(None) };
    static ENTROPY_PREPARES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
fn entropy_service_result(case: EntropyReplyCase) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation, entropy};
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    let invalid = matches!(case, EntropyReplyCase::InvalidFlags);
    let fault = matches!(case, EntropyReplyCase::FirstFault) || invalid;
    let cancel = matches!(
        case,
        EntropyReplyCase::CancelBeforeReply | EntropyReplyCase::CancelAfterReply
    );
    if fault {
        service.prepare_copy_error = Some(NativeProcessError::Fault);
    }
    let prefix = matches!(case, EntropyReplyCase::Prefix);
    let address = UserVa::new(if prefix { 0x10ff8 } else { 0x10000 });
    ENTROPY_WRITABLE_END.with(|limit| limit.set(prefix.then_some(UserVa::new(0x11000))));
    ENTROPY_PREPARES.with(|count| count.set(0));
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
        assert!(matches!(
            entry
                .begin_entropy_service(
                    address,
                    if prefix { 13 } else { 8 },
                    NativeEntropyFlags::from_bits_retain(if invalid { 6 } else { 0 }),
                    carrick_guest_arch::GuestLen::new(if prefix { 13 } else { 16 })
                )
                .unwrap(),
            NativeResume::Left(None)
        ));
    }
    assert_eq!(
        ENTROPY_PREPARES.with(|count| count.get()),
        if invalid {
            0
        } else if prefix {
            2
        } else {
            1
        },
        "prepare each accessible page once before requesting entropy"
    );
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // A stale MM incarnation cannot claim or consume this retained allocation.
    // SAFETY: fixture owns the member and its exact service queue.
    assert!(
        unsafe {
            ServiceCell::claim_notice(
                &fixture.control.service,
                notice,
                NonZeroU64::new(2).unwrap(),
                fixture.zone.record(fixture.record.id).identity(),
            )
        }
        .is_err()
    );
    // SAFETY: same queue, now with the requesting MM's live incarnation.
    let ticket = unsafe {
        ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(fixture.record.id).identity(),
        )
    }
    .unwrap();
    if !matches!(case, EntropyReplyCase::CancelBeforeReply) {
        let ServiceOperation::Entropy { payload } = ticket.request().operation else {
            panic!("entropy ticket");
        };
        // SAFETY: pending service owns staging until this ticket settles.
        let record = unsafe {
            core::slice::from_raw_parts_mut(
                payload.address().raw() as *mut u8,
                payload.length().raw() as usize,
            )
        };
        assert_eq!(
            entropy::request(record).unwrap().capacity,
            if fault { 0 } else { 8 }
        );
        carrick_kernel::dispatch::serve_native_entropy(record).unwrap();
    }
    drop(queue);
    if cancel {
        fixture
            .runtime
            .cancel_service(fixture.record, fixture.slot, &mut service)
            .unwrap();
    }
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    assert!(
        ticket
            .complete(!matches!(case, EntropyReplyCase::CancelBeforeReply))
            .is_ok()
    );
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);
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
    let expected = match case {
        EntropyReplyCase::FirstFault => -14,
        EntropyReplyCase::InvalidFlags => -22,
        EntropyReplyCase::CancelBeforeReply => -4,
        EntropyReplyCase::Prefix | EntropyReplyCase::CancelAfterReply => 8,
    };
    assert!(
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(result) if result.raw() == expected)
    );
    let copied = take_signal_copies();
    if expected > 0 {
        assert_eq!(copied.len(), 1);
        assert_eq!(copied[0].0, address);
        assert_eq!(copied[0].1.len(), 8);
    } else {
        assert!(copied.is_empty());
    }
}

#[test]
#[cfg(test)]
fn entropy_service_preparation_busy_retries_before_generation() {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.prepare_copy_error = Some(NativeProcessError::Busy);
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
        assert!(matches!(
            entry
                .begin_entropy_service(
                    UserVa::new(0x10000),
                    8,
                    NativeEntropyFlags::from_bits_retain(0),
                    carrick_guest_arch::GuestLen::new(8)
                )
                .unwrap(),
            NativeResume::Left(None)
        ));
    }
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // SAFETY: fixture retains the exact member and service queue.
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
    drop(queue);
    // A handled signal does not turn internal MM preparation into EFAULT.
    fixture
        .runtime
        .cancel_service(fixture.record, fixture.slot, &mut service)
        .unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);
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
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::RetrySyscall
    ));
    assert!(take_signal_copies().is_empty());
    assert!(fixture.task.service_notice.take().unwrap().is_none());
    assert!(matches!(
        entry
            .begin_entropy_service(
                UserVa::new(0x10000),
                8,
                NativeEntropyFlags::from_bits_retain(0),
                carrick_guest_arch::GuestLen::new(8)
            )
            .unwrap(),
        NativeResume::Left(None)
    ));
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // SAFETY: the same member now owns a fresh, authenticated entropy ticket.
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
        ServiceOperation::Entropy { .. }
    ));
    assert!(ticket.complete(false).is_ok());
    drop(queue);
}

#[cfg(test)]
std::thread_local! {
    static ENTROPY_PREPARE_BUSY_ONCE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    static ENTROPY_DOORBELL: core::cell::RefCell<Option<Box<dyn FnMut()>>> = const { core::cell::RefCell::new(None) };
}

/// Answer the Physical carrier's native-service doorbell with `hook`, or
/// restore the unanswered doorbell with `None`.
#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn on_service_doorbell(hook: Option<Box<dyn FnMut()>>) {
    ENTROPY_DOORBELL.with(|slot| *slot.borrow_mut() = hook);
}

/// The synchronous CPL0 crossing ACKs before enrollment. Drive the same
/// production entropy entry and prove its bytes still resume via the owner.
#[test]
#[cfg(test)]
fn entropy_physical_checkpoint_ack_before_park_resumes_exact_output() {
    entropy_physical_checkpoint(false);
}

#[test]
#[cfg(test)]
fn entropy_physical_checkpoint_busy_once_then_success() {
    entropy_physical_checkpoint(true);
}

#[cfg(test)]
fn entropy_physical_checkpoint(busy: bool) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    let capacity = NativeServiceCapacityFixture::new(1);
    let (record, address, saved) = capacity.select().unwrap();
    let fixture = &capacity.fixture;
    assert!(fixture.zone.record(record.id).is_native_owned());
    let parent = fixture.runtime.graph.lock().root_key;
    assert!(fixture.runtime.task_binding(parent).is_some());
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let task = fixture.task;
    let zone = fixture.zone;
    let identity = zone.record(record.id).identity();
    // SAFETY: the production fork published this fixture-retained child control.
    let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    let crossings = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let counted = crossings.clone();
    ENTROPY_DOORBELL.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
            let notice = task.service_notice.take().unwrap().unwrap();
            let key =
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap();
            let queue = zone
                .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                    crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                })
                .unwrap();
            let member = queue.native_service_member(record).unwrap();
            // SAFETY: fixture retains this exact initialized member under its queue.
            let ticket = unsafe {
                ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, member)
            }
            .unwrap();
            drop(queue);
            match ticket.request().operation {
                ServiceOperation::Entropy { payload } => {
                    // SAFETY: the production pending service retains this staging box.
                    let bytes = unsafe {
                        core::slice::from_raw_parts_mut(
                            payload.address().raw() as *mut u8,
                            payload.length().raw() as usize,
                        )
                    };
                    carrick_kernel::dispatch::serve_native_entropy(bytes).unwrap();
                }
                ServiceOperation::CarrierWork { .. } if busy => {}
                _ => panic!("entropy or its retained preparation"),
            }
            let _queue = zone
                .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                    crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                })
                .unwrap();
            assert!(ticket.complete(true).is_ok());
        }))
    });
    take_signal_copies();
    ENTROPY_PREPARE_BUSY_ONCE.with(|once| once.set(busy));
    let mut service = fixture.service();
    {
        let mut entry = fixture
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
        assert!(
            entry.is_fork_child(),
            "select from authenticated process custody"
        );
        assert!(matches!(
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::NoPending
        ));
        assert!(matches!(
            entry
                .begin_entropy_call(NativeEntropyArgs {
                    address: UserVa::new(0x10000),
                    length: carrick_guest_arch::GuestLen::new(8),
                    flags: NativeEntropyFlags::from_bits_retain(0)
                })
                .unwrap(),
            NativeResume::Left(None)
        ));
    }
    if busy {
        assert_eq!(zone.switch_in_full(fixture.slot).unwrap().record, record.id);
        // SAFETY: fixture owns the selected continuation and its saved words.
        let saved = unsafe { fixture.runtime.record_binding(record) }
            .unwrap()
            .words;
        let mut entry = fixture
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
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::RetrySyscall
        ));
        assert!(take_signal_copies().is_empty());
        assert!(matches!(
            entry
                .begin_entropy_call(NativeEntropyArgs {
                    address: UserVa::new(0x10000),
                    length: carrick_guest_arch::GuestLen::new(8),
                    flags: NativeEntropyFlags::from_bits_retain(0)
                })
                .unwrap(),
            NativeResume::Left(None)
        ));
    }
    ENTROPY_DOORBELL.with(|hook| *hook.borrow_mut() = None);
    let expected_crossings = if busy { 2 } else { 1 };
    assert_eq!(crossings.load(Ordering::Relaxed), expected_crossings);
    assert!(
        take_signal_copies().is_empty(),
        "physical ACK cannot bypass owner copyout"
    );
    assert!(task.service_notice.take().unwrap().is_none());
    assert_eq!(zone.switch_in_full(fixture.slot).unwrap().record, record.id);
    // SAFETY: switch-in selected this fixture-owned exact record.
    let saved = unsafe { fixture.runtime.record_binding(record) }
        .unwrap()
        .words;
    let mut entry = fixture
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
    assert!(
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(result) if result.raw() == 8)
    );
    let copies = take_signal_copies();
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].0, UserVa::new(0x10000));
    assert_eq!(copies[0].1.len(), 8);
    assert_eq!(
        crossings.load(Ordering::Relaxed),
        expected_crossings,
        "no regenerated request"
    );
}

#[cfg(test)]
std::thread_local! {
    static FAULT_REPLY_WAIT_ONCE: core::cell::Cell<Option<carrick_core_abi::PortalOwnerWait>> = const { core::cell::Cell::new(None) };
    static FAULT_REPLY_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static FAULT_REPLY_LAST_CANCEL: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[test]
#[cfg(test)]
fn entropy_fault_refusal_returns_prepared_prefix() {
    entropy_fault_completion(false);
}

#[test]
#[cfg(test)]
fn entropy_fault_cancel_waits_once_then_settles() {
    entropy_fault_completion(true);
}

#[cfg(test)]
fn entropy_fault_completion(cancel_wait: bool) {
    use carrick_core_abi::service::{ServiceCell, ServiceOperation, entropy};
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    let address = UserVa::new(if cancel_wait { 0x10000 } else { 0x10ff8 });
    let length = if cancel_wait { 8 } else { 16 };
    service.child_copy_error = Some(NativeProcessError::Unsupported);
    service.child_copy_error_at = Some(if cancel_wait { address.raw() } else { 0x11000 });
    take_signal_copies();
    FAULT_REPLY_CALLS.with(|calls| calls.set(0));
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
            entry
                .begin_entropy_service(
                    address,
                    length,
                    NativeEntropyFlags::from_bits_retain(0),
                    carrick_guest_arch::GuestLen::new(length as u64)
                )
                .unwrap(),
            NativeResume::Left(None)
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let key =
        carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap();
    let queue = fixture
        .zone
        .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
        .unwrap();
    // SAFETY: the real pending owner and this queue retain the exact control.
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
        ServiceOperation::Fault(_)
    ));
    drop(queue);
    let gate = if cancel_wait {
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
        let observed = space
            .notifications(handle.incarnation())
            .unwrap()
            .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
        let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
        access.raise(space.index());
        // SAFETY: exact source observed before the injected refusal.
        let wait = unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                handle,
                carrick_core_abi::PortalWaitCause::Gate,
                observed.revision(),
            )
        };
        FAULT_REPLY_WAIT_ONCE.with(|once| once.set(Some(wait)));
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        fixture
            .control
            .service
            .cancel(ticket.request().identity)
            .unwrap();
        drop(queue);
        Some((access, space.index()))
    } else {
        None
    };
    let queue = fixture
        .zone
        .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        })
        .unwrap();
    assert!(ticket.complete(false).is_ok());
    queue
        .notify_object(fixture.slot, &mut WakeEffects::default())
        .unwrap();
    drop(queue);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
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
            entry.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::Left(None)
        ));
    }
    if let Some((access, index)) = gate {
        assert!(take_signal_copies().is_empty());
        access.open(index);
    } else {
        let notice = fixture.task.service_notice.take().unwrap().unwrap();
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
        let ticket = unsafe {
            ServiceCell::claim_notice(
                &fixture.control.service,
                notice,
                NonZeroU64::MIN,
                fixture.zone.record(fixture.record.id).identity(),
            )
        }
        .unwrap();
        let ServiceOperation::Entropy { payload } = ticket.request().operation else {
            panic!("prepared entropy prefix");
        };
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                payload.address().raw() as *mut u8,
                payload.length().raw() as usize,
            )
        };
        assert_eq!(entropy::request(bytes).unwrap().capacity, 8);
        bytes[entropy::ENTROPY_HEADER_BYTES..].fill(0x76);
        entropy::publish_reply(bytes, 8).unwrap();
        assert!(ticket.complete(true).is_ok());
        queue
            .notify_object(fixture.slot, &mut WakeEffects::default())
            .unwrap();
        drop(queue);
    }
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
        matches!(entry.resume_checkpoint(|_| Ok(None)).unwrap(), NativeResume::Returned(result)
        if result.raw() == if cancel_wait { -14 } else { 8 })
    );
    let copies = take_signal_copies();
    if cancel_wait {
        assert!(copies.is_empty());
        assert_eq!(FAULT_REPLY_CALLS.with(|calls| calls.get()), 2);
        assert!(
            FAULT_REPLY_LAST_CANCEL.with(|cancel| cancel.get()),
            "a repark must retain cancellation intent"
        );
    } else {
        assert_eq!(copies, vec![(address, vec![0x76; 8])]);
    }
    assert_eq!(fixture.page.claimed_count(), 0);
}

#[cfg(test)]
#[test]
fn host_root_open_publishes_unstamped_record_through_service_notice() {
    let fixture = NativeSignalFixture::admit_host_root(
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
    let counters = Box::leak(Box::new(carrick_el1_abi::Counters::new()));
    let mut service = fixture.service();
    let mut root = fixture
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
    let path = b"/lib/libc.so.6";
    let mut open =
        alloc::vec![0u8; carrick_core_abi::host_file::record_len(path.len(), 0).unwrap()];
    carrick_core_abi::host_file::encode(
        &mut open,
        carrick_core_abi::host_file::HostFileHeader {
            op: carrick_core_abi::host_file::HostFileOp::Openat,
            table: [1, 1, 1],
            fd: -100,
            flags: 0,
            args: [0; 4],
        },
        path,
        0,
    )
    .unwrap();

    assert!(matches!(
        root.begin_host_file_call(
            open.into_boxed_slice(),
            None,
            true,
            None,
            false,
            NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(257), counters)
        ),
        Ok(NativeResume::Left(None))
    ));
    drop(root);
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(fixture.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // SAFETY: fixture retains the control and exact member under its queue.
    let ticket = unsafe {
        carrick_core_abi::service::ServiceCell::claim_notice(
            &fixture.control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(fixture.record.id).identity(),
        )
    }
    .unwrap();
    assert_eq!(
        ticket.request().identity.birth.origin,
        carrick_core_abi::service::ServiceOrigin::Initial
    );
    let carrick_core_abi::service::ServiceOperation::HostFile { payload, .. } =
        ticket.request().operation
    else {
        panic!("host file notice expected")
    };
    // SAFETY: ticket retains the request box; no ring execution can mutate it.
    let record = unsafe {
        core::slice::from_raw_parts_mut(
            payload.ring_storage().raw() as *mut u8,
            payload.length().raw() as usize,
        )
    };
    let view = carrick_core_abi::host_file::HostFileRequestView::parse(record).unwrap();
    assert_eq!(view.input(), path);
    assert_eq!(counters.refused[257].load(Ordering::Relaxed), 0);
    assert!(ticket.complete(false).is_ok());
    drop(queue);
}

#[cfg(test)]
#[test]
fn production_unmapped_root_early_bind_admits_and_forks() {
    production_unmapped_root_admits_and_forks(false);
}

#[cfg(test)]
#[test]
fn production_unmapped_root_late_bind_admits_and_forks() {
    production_unmapped_root_admits_and_forks(true);
}

#[cfg(test)]
fn production_unmapped_root_admits_and_forks(late_bind: bool) {
    use carrick_hal::birth_serial::test_support::OwnedBirthZone;
    use carrick_kernel::kernel::{Container, Kernel, LaunchContext, RootBootstrap, RunId};
    {
        let mut retained = None;
        let fixture = NativeSignalFixture::from_bootstrap(|zone| {
            let source = Arc::new(OwnedBirthZone::from_static(zone));
            let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
                "unmapped",
            ))));
            assert!(container.pid_region().is_none());
            let mut bootstrap = RootBootstrap::for_prepared_launch(
                41,
                carrick_hal::ThreadId::synthetic_for_tests(41),
                "unmapped".into(),
                container,
                Arc::new(carrick_hal::NullHostSignalBridge::default()),
            )
            .unwrap();
            if !late_bind {
                bootstrap = bootstrap.with_birth_source(source.clone());
            }
            let (kernel, root) = Kernel::bootstrap_root(bootstrap).unwrap();
            if late_bind {
                kernel.bind_initial_birth_source(source).unwrap();
            }
            let task = root.task().key();
            let thread = root.thread().key();
            let binding = ExecutionBinding {
                task: carrick_core_abi::EntryTaskKey::from_raw(task.id.raw() as u64),
                generation: carrick_core_abi::SnapshotGeneration::INITIAL,
                mm: carrick_core_abi::EntryMmKey::from_raw(1),
                thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(
                    thread.serial.raw(),
                ),
            };
            retained = Some((kernel, root));
            (
                binding,
                binding.task,
                carrick_core_abi::BirthSerial::of_task(task.serial),
            )
        });
        assert_eq!(fixture.task.visible_pid(), Some(41));
        let (kernel, _root) = retained.as_ref().unwrap();
        let (host_id, _host_claim) = kernel.ids().reserve_task().unwrap();
        let (host_id2, _host_claim2) = kernel.ids().reserve_task().unwrap();
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
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("native fork did not return");
        };
        drop(entry);
        let child_pid = result.raw();
        let child_entry = fixture
            .child_page
            .entry_ref_for_visible_tid(child_pid as u32)
            .unwrap();
        let child_identity = fixture.child_page.identity(child_entry).unwrap();
        assert_eq!(child_identity.tid, child_pid as u32);
        assert_eq!(child_identity.visible_tid, child_pid as u32);
        let child_control = service
            .child_lifecycle(&fixture.address)
            .born_slot(child_entry)
            .unwrap();
        assert_eq!(child_control.visible_tid(), Some(child_pid as u32));
        assert!(child_pid > 0);
        assert_ne!(child_pid, 41);
        assert_ne!(child_pid, host_id.raw() as i64);
        assert_ne!(child_pid, host_id2.raw() as i64);
        assert!(
            fixture
                .zone
                .namespace()
                .with_view(&carrick_sched_core::ShortLockSpin, |ns| ns
                    .is_reserved_number(child_pid as i32)),
            "unmapped visible PID must be its internal claim"
        );
    }
}

/// Fresh-root storage uses the same issuer, limits, rollback and release
/// notification path as fork-child stock; no sibling context is supplied.
#[test]
#[cfg(test)]
fn native_root_stock_claim_rollback_and_nproc_limit() {
    use carrick_personality_linux::identity::ProcessIdentityVenue;
    use carrick_personality_linux::lifecycle::ThreadBirthAdmission;
    use carrick_personality_linux::sysinfo::ProcessSysinfoVenue;
    let fixture = native_exec_fixture();
    let controls = Box::leak(Box::new(core::array::from_fn::<_, 9, _>(|_| {
        ThreadControlSlot::new()
    })));
    fixture
        .runtime
        .admit_thread_stock(NativeLifecycleResources {
            page: fixture.page,
            controls,
        })
        .unwrap();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
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
        entry.prepare_thread_birth(),
        ThreadBirthAdmission::Ready
    ));
    let before = thread_stock::claim_counts(&fixture.runtime);
    fixture.page.close_for_fork().unwrap();
    assert!(matches!(
        entry.prepare_thread_birth(),
        ThreadBirthAdmission::Ready
    ));
    fixture.page.reopen_after_fork().unwrap();
    assert_eq!(thread_stock::claim_counts(&fixture.runtime), before);
    let claim = fixture.page.claim_any().unwrap();
    let identity = fixture.page.identity(claim.entry()).unwrap();
    assert_ne!(identity.tid, 41);
    fixture.page.unclaim(claim).unwrap();
    entry.lifecycle_admission_settled().unwrap();
    assert!(matches!(
        entry.prepare_thread_birth(),
        ThreadBirthAdmission::Ready
    ));
    assert_eq!(
        thread_stock::claim_counts(&fixture.runtime),
        before,
        "rollback must not issue replacement identities"
    );
    entry
        .set_rlimit(
            carrick_abi::LinuxResource::Nproc.index(),
            carrick_sched_core::process::LinuxRlimit {
                rlim_cur: 1,
                rlim_max: 1,
            },
        )
        .unwrap();
    entry.set_uid(1000).unwrap();
    assert!(
        matches!(entry.prepare_thread_birth(),ThreadBirthAdmission::Owned(LifecycleOutcome::Returned {result,..}) if result.raw()==-11)
    );
    assert_eq!(fixture.page.live(), 1);
}

#[test]
#[cfg(test)]
fn native_root_stock_busy_claim_parks_then_release_retries_same_clone() {
    use carrick_personality_linux::lifecycle::ThreadBirthAdmission;
    let fixture = native_exec_fixture();
    let controls = Box::leak(Box::new(core::array::from_fn::<_, 9, _>(|_| {
        ThreadControlSlot::new()
    })));
    fixture
        .runtime
        .admit_thread_stock(NativeLifecycleResources {
            page: fixture.page,
            controls,
        })
        .unwrap();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
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
    let mut claims = Vec::new();
    for _ in 0..carrick_el1_abi::THREAD_POOL_ENTRIES {
        assert!(matches!(
            entry.prepare_thread_birth(),
            ThreadBirthAdmission::Ready
        ));
        claims.push(fixture.page.claim_any().unwrap());
    }
    assert!(
        matches!(
            entry.prepare_thread_birth(),
            ThreadBirthAdmission::Owned(LifecycleOutcome::Transferred { .. })
        ),
        "busy stock must park, never return EAGAIN or fail the run"
    );
    assert!(entry.take_run_failure().is_none());
    assert!(entry.take_handoff_receipt().is_some());
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);
    let claim = claims.pop().unwrap();
    let released = claim.entry();
    fixture.page.unclaim(claim).unwrap();
    entry.lifecycle_admission_settled().unwrap();
    drop(entry);
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
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
        entry.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::RetrySyscall
    ));
    assert!(matches!(
        entry.prepare_thread_birth(),
        ThreadBirthAdmission::Ready
    ));
    let retry = fixture.page.claim_any().unwrap();
    assert_eq!(
        retry.entry(),
        released,
        "retry must consume the returned standing identity"
    );
    fixture.page.unclaim(retry).unwrap();
    for claim in claims {
        fixture.page.unclaim(claim).unwrap();
    }
    entry.lifecycle_admission_settled().unwrap();
    let outcome = entry.exit_group(7);
    assert!(matches!(outcome, LifecycleOutcome::Transferred { .. }));
    assert!(entry.take_run_failure().is_none());
    assert!(entry.take_root_exit().is_some());
    assert_eq!(fixture.page.live(), 0);
    for index in 0..fixture.page.entry_count() {
        assert!(matches!(
            fixture.page.state(index),
            Some((_, carrick_el1_abi::EntryState::Revoked))
        ));
    }
}

#[test]
#[cfg(test)]
fn native_futex_atomic_owner_retry_keeps_deadline_and_key_scope() {
    use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest, UserCopy};
    use carrick_guest_arch::{Access, GuestLen};
    use carrick_personality_linux::sched::{ETIMEDOUT_RESULT, FutexCall};
    struct Copy {
        refuse: bool,
        loads: usize,
    }
    impl UserCopy for Copy {
        fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> CopyOutcome {
            assert_eq!(dst.len(), 8);
            dst.copy_from_slice(&(if src.raw() == 0x2000 { 1_u64 } else { 0 }).to_le_bytes());
            CopyOutcome::Done
        }
        fn copy_out(&mut self, _: UserVa, _: &[u8]) -> CopyOutcome {
            panic!("futex must not write guest bytes")
        }
        fn atomic_load_u32(&mut self, address: UserVa, out: &mut u32) -> CopyOutcome {
            assert_eq!(address, UserVa::new(0x1000));
            self.loads += 1;
            if core::mem::take(&mut self.refuse) {
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
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
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
    let mut copy = Copy {
        refuse: true,
        loads: 0,
    };
    let call = FutexCall {
        args: [0x1000, 128, 0, 0x2000, 0, 0],
    };
    assert!(matches!(
        entry.native_futex(call, &mut copy),
        Some(LifecycleOutcome::Redispatch)
    ));
    assert_eq!(copy.loads, 1);
    assert!(fixture.zone.timer_deadline(fixture.slot).is_none());
    // Advance the physical clock after owner preparation, then redispatch the
    // exact operation. Its original deadline is already 2000, not 3000.
    fixture
        .zone
        .counters
        .el1_timeouts
        .store(1, Ordering::Release);
    assert!(matches!(
        entry.native_futex(call, &mut copy),
        Some(LifecycleOutcome::Transferred { .. })
    ));
    assert_eq!(copy.loads, 2);
    assert_eq!(fixture.zone.timer_deadline(fixture.slot), Some(2000));
    assert!(entry.take_handoff_receipt().is_some());
    let shared_key =
        carrick_personality_linux::sched::MmFutexKey::shared_private(UserVa::new(0x1000))
            .unwrap()
            .scheduler_address();
    let guard = fixture.zone.short_lock(
        ZoneTables::<ParkedContextWords>::bucket_of_with_context(1, shared_key),
        &carrick_sched_core::ShortLockSpin,
    );
    let mut effects = WakeEffects::default();
    assert_eq!(
        fixture.zone.wake_placed(
            &guard,
            1,
            shared_key,
            u32::MAX,
            1,
            Waker::El1 { slot: fixture.slot },
            &mut [],
            &mut effects
        ),
        0,
        "a shared wake cannot release a PRIVATE waiter"
    );
    drop(guard);
    assert_eq!(fixture.zone.timer_deadline(fixture.slot), Some(2000));
    assert_eq!(
        fixture
            .zone
            .expire_timer(fixture.slot, 2000, ETIMEDOUT_RESULT, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            },),
        Ok(true)
    );
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().result,
        Some(ETIMEDOUT_RESULT)
    );
    assert_eq!(fixture.zone.timer_node_count(), 0);
    assert_eq!(
        copy.loads, 2,
        "expiry must not re-read or replay the guest comparison"
    );
}

#[test]
#[cfg(test)]
fn native_futex_unplaceable_wake_keeps_mask_count_and_placement_custody() {
    use carrick_personality_linux::sched::FutexCall;
    use carrick_sched_core::{Claim, ShortLockSpin};
    let fixture = native_exec_fixture();
    let zone = fixture.zone;
    let away = SlotId::new(1);
    zone.drive(away, 2);
    zone.publish_slot(away, 1, Some(1), 1);
    zone.enter_guest(away);
    zone.install_space(away, 1).unwrap();
    let mut records = Vec::new();
    for mask in [2, 1, 1] {
        let mut identity = zone.record(fixture.record.id).identity();
        identity.tid += records.len() as u64 + 1;
        identity.affinity = 2;
        let id = zone.alloc_record(identity).unwrap();
        let record = zone.record_ref(id);
        assert!(zone.mark_native_owned(id));
        let seq = zone.next_seq(id);
        let guard = zone.short_lock(
            ZoneTables::<ParkedContextWords>::bucket_of_with_context(1, 0x1000),
            &ShortLockSpin,
        );
        zone.enqueue(&guard, id, seq, 1, 0x1000, mask, 0).unwrap();
        zone.publish_park(id, seq);
        records.push(record);
    }
    zone.step_back(away, 2);
    let mut service = fixture.service();
    let saved = words(fixture.address);
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
            &saved,
            &mut service,
        )
        .unwrap();
    struct NoCopy;
    impl carrick_core::user_copy::UserCopy for NoCopy {
        fn copy_in(&mut self, _: &mut [u8], _: UserVa) -> carrick_core::user_copy::CopyOutcome {
            panic!("address-only wake")
        }
        fn copy_out(&mut self, _: UserVa, _: &[u8]) -> carrick_core::user_copy::CopyOutcome {
            panic!("address-only wake")
        }
    }
    assert!(
        matches!(entry.native_futex(FutexCall { args: [0x1000, 138, 1, 0, 0, 1] }, &mut NoCopy), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == 1)
    );
    assert!(entry.take_run_failure().is_none());
    // The waiter's only allowed slot is busy: the wake still finished in
    // the ring (#1941), queuing it there with a reschedule rather than
    // refusing it to a second placement pass.
    assert_eq!(
        records
            .iter()
            .filter(|r| matches!(
                zone.record(r.id).claim(),
                Claim::Queued { slot, .. } if slot == away
            ))
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| matches!(zone.record(r.id).claim(), Claim::Parked { .. }))
            .count(),
        2
    );
    // Returning the eligible driver consumes the retained scheduler custody.
    zone.drive(away, 2);
    zone.enter_guest(away);
    zone.install_space(away, 1).unwrap();
    let selected = zone.switch_in_full(away).unwrap();
    assert!(records[1..].iter().any(|r| r.id == selected.record));
    assert_eq!(selected.result, Some(0));
    assert!(
        matches!(entry.native_futex(FutexCall { args: [0x1000, 138, 1, 0, 0, 1] }, &mut NoCopy), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == 1)
    );
    assert!(
        matches!(entry.native_futex(FutexCall { args: [0x1000, 138, 1, 0, 0, 1] }, &mut NoCopy), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == 0)
    );
    assert!(
        matches!(zone.record(records[0].id).claim(), Claim::Parked { .. }),
        "nonmatching mask must stay asleep"
    );
}

#[cfg(test)]
#[path = "tests/futex_contention.rs"]
mod futex_contention;

#[cfg(test)]
#[path = "tests/x86_switch_in_binding.rs"]
mod x86_switch_in_binding;

#[cfg(all(test, not(target_os = "macos")))]
#[test]
fn invalid_copy_ranges_are_efault_before_owner_preparation() {
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    // No invalid user range may reach an owner operation. If it does, this
    // deliberately refusing physical service exposes the missing admission.
    service.prepare_copy_error = Some(NativeProcessError::Invalid);
    service.child_copy_error = Some(NativeProcessError::Invalid);
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
    for raw in [
        u64::MAX - 3,
        carrick_guest_arch::USER_CEILING - 3,
        carrick_guest_arch::USER_CEILING,
    ] {
        let address = UserVa::new(raw);
        let input = entry.wait_guest_copy(carrick_core::user_copy::GuestCopyRequest {
            address,
            len: carrick_guest_arch::GuestLen::new(8),
            access: carrick_guest_arch::Access::Read,
        });
        assert!(matches!(input, LifecycleOutcome::Returned { result, .. } if result.raw() == -14));
        let output = entry.complete_copyout(address, vec![0; 8], SyscallResult::new(0));
        assert!(matches!(output, LifecycleOutcome::Returned { result, .. } if result.raw() == -14));
    }
    assert!(entry.take_handoff_receipt().is_none());
    assert!(entry.take_run_failure().is_none());
    assert!(
        service.copies.is_empty(),
        "bad addresses cannot publish bytes"
    );
}

#[cfg(all(test, not(target_os = "macos")))]
#[test]
fn owner_copyout_invariant_is_a_run_failure() {
    let fixture = native_exec_fixture();
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.child_copy_error = Some(NativeProcessError::Invalid);
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
    let outcome = entry.complete_copyout(UserVa::new(0x10000), vec![0; 8], SyscallResult::new(0));
    assert!(matches!(outcome, LifecycleOutcome::Transferred { .. }));
    assert_eq!(
        entry.take_run_failure(),
        Some(carrick_core_abi::NativeRunFailureReason::NativeInvalid)
    );
    assert!(service.copies.is_empty());
}

#[cfg(all(test, not(target_os = "macos")))]
#[test]
fn native_zone_poll_signal_before_enrolment_completes_eintr_and_delivers_once() {
    use crate::file_table::{LINUX_POLLIN, PollFd};
    use carrick_el1_abi::ipc::{IpcBacking, IpcLimits, fd, pipe::End, pipe::WaitFor};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable};
    use carrick_personality_linux::dispatch::{CompletionRoute, SyscallFrame};
    use carrick_test_support::GuestUserBuffer;
    use zerocopy::IntoBytes;

    struct NativePollTrapFrame(carrick_el1_abi::TrapFrame);

    impl SyscallFrame for NativePollTrapFrame {
        fn task_index(&self) -> usize {
            self.0.task_index()
        }
        fn slot(&self) -> Option<SlotId> {
            self.0.slot()
        }
        fn canonical_ordinal(&self) -> carrick_syscall_abi::CanonicalNr {
            carrick_syscall_abi::nr::PPOLL
        }
        fn argument(&self, index: usize) -> Option<u64> {
            self.0.argument(index)
        }
        fn result(&self) -> carrick_guest_arch::NativeReturnWord {
            self.0.result()
        }
        fn set_result(&mut self, word: carrick_guest_arch::NativeReturnWord) {
            self.0.set_result(word);
        }
        fn user_sp(&self) -> Option<carrick_core_abi::UserVa> {
            self.0.user_sp()
        }
    }

    impl crate::dispatch::GuestDispatchFrame for NativePollTrapFrame {
        fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
            carrick_guest_arch::NativeOrdinal::new(
                carrick_syscall_abi::syscall_x86_64::X86_PPOLL.raw(),
            )
        }
        fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
            carrick_personality_linux::crossing::HostCrossingSet::X86
        }
        fn settles_owed_work_at_continuation_boundary(&self) -> bool {
            true
        }
        fn may_serve_poll(&self) -> bool {
            true
        }
        fn operation_resume_pc(
            &self,
        ) -> Option<carrick_el1::substrate::sched::object_wait::OperationResumePc> {
            carrick_el1::substrate::sched::object_wait::OperationResumePc::from_raw(
                self.0.elr.wrapping_sub(2),
            )
        }
        fn poll_timeout_kind(&self) -> crate::dispatch::PollTimeoutKind {
            crate::dispatch::PollTimeoutKind::Timespec
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

    let fixture = native_exec_fixture();
    fixture.install_sigint_handler(false);

    let host: &'static Arc<HostIpc> = Box::leak(Box::new(Arc::new(
        HostIpc::with_limits(1 << 20, IpcLimits::ZONE).unwrap(),
    )));
    fixture
        .zone
        .bind_ipc_operation_slots(
            host.region().operation_slot_generation(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| {
                let _ = owned.into_parts();
            },
        )
        .unwrap();

    let table = HostTable::create(host.clone(), 64, 8).unwrap();
    let pipe = host.create_pipe(65536).unwrap();
    for lane in [WaitFor::Readable, WaitFor::Writable] {
        let key = carrick_el1_abi::ipc::object_wait_key(pipe, lane).unwrap();
        fixture
            .zone
            .bind_object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            })
            .unwrap();
    }
    let reader = host
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object: pipe,
                end: End::Reader,
            }
            .encode(),
            fd::AccessMode::ReadOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    reader.install(table.id(), fd::Fd(3), false).unwrap();
    drop(reader);
    let writer = host
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object: pipe,
                end: End::Writer,
            }
            .encode(),
            fd::AccessMode::WriteOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    writer.install(table.id(), fd::Fd(4), false).unwrap();
    drop(writer);

    let map = Box::leak(Box::new(unsafe {
        core::mem::zeroed::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    }));
    map.publish_owned(5, table.id().to_raw()).unwrap();
    let tables = Box::leak(Box::new(crate::ipc::MapTables(map)));
    let venue = crate::ipc::IpcVenue {
        region: host.region(),
        tables,
    };

    let pollfd_buf = GuestUserBuffer::from_value(PollFd {
        fd: 3,
        events: LINUX_POLLIN,
        revents: 0x5a5a,
    });

    // 1. Deliverable signal is pending before object-wait enrolment.
    let sigint = carrick_signal_core::policy::Signal::from_number(2).unwrap();
    fixture
        .runtime
        .current_signals(fixture.task)
        .unwrap()
        .enqueue_thread(fixture.record, sigint, None);
    assert!(fixture.registry_signal_checkpoint_needed());

    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let mut service = fixture.service();
    service.native_ipc = Some(host.region());
    let mut frame = NativePollTrapFrame(carrick_el1_abi::TrapFrame {
        elr: 0x4004,
        ..Default::default()
    });
    frame.0.x[8] = carrick_syscall_abi::nr::PPOLL.raw();
    frame.0.x[0] = pollfd_buf.arg();
    frame.0.x[1] = 1;
    frame.0.x[2] = 0;
    frame.0.x[3] = 0;

    // 2. First poll entry enrols on the empty pipe and runs the post-enrolment
    // interrupt() probe, which immediately wakes the waiter with Handback::Signal.
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
        let route = crate::dispatch::dispatch_syscall_with_native::<
            _,
            crate::sched::FakeCpu,
            crate::sched::HardwareUserWord,
            _,
            carrick_sched_core::ParkedContextWords,
        >(
            &mut frame,
            &carrick_el1_abi::Counters::new(),
            core::slice::from_ref(fixture.task),
            &[],
            &[],
            &[],
            &[],
            &carrick_el1_abi::InotifyNameCache::new(),
            None,
            Some(&venue),
            None,
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(route, CompletionRoute::Suspended);
        assert!(entry.take_handoff_receipt().is_none());
    }
    assert_eq!(
        fixture.zone.record(fixture.record.id).handback(),
        Some(carrick_sched_core::Handback::Signal),
        "post-enrolment interrupt probe must wake the parked poll with Handback::Signal"
    );
    assert!(
        fixture
            .zone
            .record(fixture.record.id)
            .has_adapter_operation(),
        "adapter operation token remains attached until the retried poll consumes Handback::Signal"
    );
    fixture
        .task
        .linux
        .take_host_work_doorbell()
        .expect("post-enrolment interrupt probe must raise the host-work doorbell")
        .settled();
    let mut handed_back = Vec::new();
    fixture
        .zone
        .take_completion_handbacks(&carrick_sched_core::ShortLockSpin, &mut |record| {
            assert!(fixture.zone.place_native_handback(record).is_some());
            handed_back.push(record);
        });
    assert_eq!(handed_back, [fixture.record]);

    let selected = fixture
        .zone
        .switch_in_full(fixture.slot)
        .expect("post-enrolment signal wake must requeue the parked poll record");
    assert_eq!(selected.record, fixture.record.id);

    // 3. On resume_checkpoint (RetrySyscall), the adapter token is still attached,
    // so matches_signal_return is false and deliver_signal_on_syscall_return is a no-op.
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
        assert!(matches!(
            entry.resume_checkpoint(|_| Ok(None)),
            Ok(NativeResume::RetrySyscall)
        ));
        assert!(
            fixture
                .zone
                .record(fixture.record.id)
                .has_adapter_operation()
        );
        assert!(
            !entry.matches_signal_return(fixture.task, fixture.control),
            "matches_signal_return must refuse signal delivery while the adapter operation token is attached"
        );
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let mut machine = HostArmSignalMachine {
            backend: HostArmBackend,
        };
        assert_eq!(
            crate::signal_delivery::deliver_signal_on_syscall_return(
                fixture.task,
                fixture.control,
                &mut entry,
                &mut frame.0,
                fp.as_bytes(),
                &mut machine,
            ),
            None
        );
        assert_eq!(
            frame.0.elr, 0x4004,
            "handler must not run before the retried poll retires its adapter token"
        );
        assert!(take_signal_copies().is_empty());
        assert!(entry.signal_checkpoint_needed());

        // 4. Retried poll consumes Handback::Signal, retires the adapter token,
        // and completes with -EINTR (-4).
        let route = crate::dispatch::dispatch_syscall_with_native::<
            _,
            crate::sched::FakeCpu,
            crate::sched::HardwareUserWord,
            _,
            carrick_sched_core::ParkedContextWords,
        >(
            &mut frame,
            &carrick_el1_abi::Counters::new(),
            core::slice::from_ref(fixture.task),
            &[],
            &[],
            &[],
            &[],
            &carrick_el1_abi::InotifyNameCache::new(),
            None,
            Some(&venue),
            None,
            Some(&mut *entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(route, CompletionRoute::Served);
        assert_eq!(frame.0.x[0] as i64, -4);
        assert!(
            !fixture
                .zone
                .record(fixture.record.id)
                .has_object_operation()
        );
        assert!(
            !fixture
                .zone
                .record(fixture.record.id)
                .has_adapter_operation(),
            "retried poll must retire the adapter operation token on EINTR"
        );
        assert!(
            entry.matches_signal_return(fixture.task, fixture.control),
            "matches_signal_return must allow signal delivery once the adapter token is retired"
        );

        // 5. Signal checkpoint on syscall return now runs the handler exactly once.
        assert_eq!(
            crate::signal_delivery::deliver_signal_on_syscall_return(
                fixture.task,
                fixture.control,
                &mut entry,
                &mut frame.0,
                fp.as_bytes(),
                &mut machine,
            ),
            None
        );
        assert_eq!(frame.0.elr, 0x7000);
        assert_eq!(frame.0.x[0], 2);
        assert_eq!(frame.0.x[30], 0x8000);
        let copies = take_signal_copies();
        assert_eq!(copies.len(), 1);
        assert!(!entry.signal_checkpoint_needed());
        assert!(!fixture.registry_signal_checkpoint_needed());

        // A second checkpoint does not deliver again.
        assert_eq!(
            crate::signal_delivery::deliver_signal_on_syscall_return(
                fixture.task,
                fixture.control,
                &mut entry,
                &mut frame.0,
                fp.as_bytes(),
                &mut machine,
            ),
            None
        );
        assert!(take_signal_copies().is_empty());
    }

    assert_eq!(
        pollfd_buf.get::<PollFd>(0).revents,
        0x5a5a,
        "EINTR must not overwrite revents"
    );
    assert!(
        host.region()
            .fd(carrick_sched_core::ShortLockSpin)
            .close(table.id(), fd::Fd(3))
            .unwrap()
            .is_some(),
        "retiring the adapter token must release the pinned reader description"
    );
}

#[cfg(test)]
struct ResidentUser;

#[cfg(test)]
impl crate::file::MemoryValidator for ResidentUser {
    fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
        len
    }
    fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
        len
    }
}

/// The x86 CPL0 `NativeService` completion arm's production body, driven with
/// an admitted native fork child and the registered root: a child's
/// `execve`/`execveat` is the native exec service's (#2235) and never settles
/// here, a root's takes the counted refusal, and neither is forwarded.
#[test]
#[cfg(test)]
fn x86_native_exec_completion_claims_the_fork_child_and_refuses_the_root() {
    use crate::dispatch::{native_exec_claimed, settle_unwired_native_service};
    use crate::native_process_runtime::NativeThreadGroupOwner as Owner;
    use carrick_guest_arch::NativeOrdinal;
    let capacity = NativeServiceCapacityFixture::new(1);
    let (child, _, _) = capacity.select().unwrap();
    let fixture = &capacity.fixture;
    let root = fixture.record;
    assert!(fixture.registry.record_is_fork_child(fixture.zone, child));
    assert!(!fixture.registry.record_is_fork_child(fixture.zone, root));
    let owner = |record| {
        if fixture.registry.record_is_fork_child(fixture.zone, record) {
            Owner::ForkChild
        } else {
            Owner::Root
        }
    };
    assert!(native_exec_claimed(|| owner(child)));
    assert!(!native_exec_claimed(|| owner(root)));

    for (native, canonical) in [(59, 221), (322, 281)] {
        // The x86 route table hands this exec to the native service; without
        // that arm the call is refused before any completion runs.
        assert_eq!(
            carrick_personality_linux::dispatch::route_x86(canonical, u64::MAX),
            carrick_personality_linux::dispatch::Family::NativeService,
            "native {native}: x86 routes exec to the native service"
        );
        let bucket = native as usize;
        let counters = carrick_el1_abi::Counters::new();
        assert_eq!(
            settle_unwired_native_service(
                fixture.registry,
                fixture.zone,
                Some(root),
                NativeOrdinal::new(native),
                &counters,
            ),
            -38,
            "native {native}: a root's exec keeps the counted refusal"
        );
        assert_eq!(counters.refused[bucket].load(Ordering::Relaxed), 1);
        assert_eq!(counters.refused_child[bucket].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[bucket].load(Ordering::Relaxed), 0);
        assert_eq!(counters.venue_refused[bucket].load(Ordering::Relaxed), 0);
    }
}

/// #2095, consuming arm: the waiter's scan selects an exited child, then a
/// sibling's birth reserves the process topology while the waiter copies the
/// child's status, so the reap (`consume_wait`) refuses with `Busy`. Busy
/// once, then success: the waiter parks on its own channel instead of
/// returning -EAGAIN, and the birth's release notification reruns it to reap
/// the child with its exact status.
#[cfg(test)]
#[test]
fn reap_refused_by_sibling_birth_parks_then_reaps() {
    use carrick_sched_core::Claim;
    // The sibling thread takes tid 42 before the root forks its child.
    let process = native_exec_fixture();
    let sibling = add_service_sibling(&process, None);
    let capacity: &'static NativeServiceCapacityFixture = Box::leak(Box::new(
        NativeServiceCapacityFixture::from_fixture(process, 1),
    ));
    let fixture = &capacity.fixture;
    let root_record = fixture.record;

    // The only child exits 5; the root's wait4(-1) wakes to reap it.
    let (child, child_address, child_words) = capacity.select().unwrap();
    assert_ne!(child, root_record);
    // The sibling's host-issued tid shifts this child's task id past its
    // namespace pid, which `select` assumes equal: publish the namespace pid.
    let child_namespace_pid = {
        let key = fixture
            .registry
            .state
            .lock()
            .members
            .values()
            .find(|member| member.record == child)
            .unwrap()
            .process;
        fixture
            .runtime
            .graph
            .lock()
            .owner
            .task(key)
            .unwrap()
            .metadata()
            .namespace_pid
    };
    fixture.task.publish_visible_pid(child_namespace_pid);
    let child_pid = i64::from(child_namespace_pid);
    let mut child_service = fixture.service();
    let mut exiting = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            child_address,
            &child_words,
            &mut child_service,
        )
        .unwrap();
    assert!(matches!(
        exiting.exit_group(5),
        LifecycleOutcome::Transferred { .. }
    ));
    drop(exiting);

    // The sibling member, live on its own slot, is the birth owner.
    let sibling_service: &'static mut Physical<'static> = Box::leak(Box::new(fixture.service()));
    let sibling_words: &'static ParkedContextWords = Box::leak(Box::new(words(fixture.address)));
    let sibling_entry: &'static mut _ = Box::leak(Box::new(
        fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: sibling.slot,
                },
                sibling.task,
                fixture.address,
                sibling_words,
                sibling_service,
            )
            .unwrap(),
    ));
    let sibling_entry: *mut _ = &mut **sibling_entry;
    let held = std::rc::Rc::new(core::cell::RefCell::new(None));
    let held_by_copy = held.clone();

    let (root, root_address, root_words) = capacity.select().unwrap();
    assert_eq!(root, root_record);
    let mut root_service = fixture.service();
    root_service.on_copy_complete = Some(Box::new(move |_| {
        if held_by_copy.borrow().is_none() {
            // SAFETY: the leaked sibling entry runs on its own slot; this
            // hook is its only user while the root's entry copies status.
            let birth = unsafe { &mut *sibling_entry }.fork_reserve().unwrap();
            *held_by_copy.borrow_mut() = Some(birth);
        }
    }));
    let mut waiter = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            root_address,
            &root_words,
            &mut root_service,
        )
        .unwrap();
    let parked = waiter.resume_checkpoint(|_| Ok(None));
    assert!(
        matches!(parked, Ok(NativeResume::Left(None))),
        "a reap refused by a sibling's birth must park, not fail: {:?}",
        parked.as_ref().map(|resume| match resume {
            NativeResume::Returned(result) => result.raw(),
            _ => 0,
        })
    );
    drop(waiter);
    assert!(held.borrow().is_some(), "the birth held during the reap");
    assert!(matches!(
        fixture.zone.record(root.id).claim(),
        Claim::Parked { .. }
    ));
    assert_eq!(root_service.copies, vec![LinuxWaitStatus::exited(5)]);

    // The birth rolls back and publishes its release, as `fork_owned` does.
    let birth = held.borrow_mut().take().unwrap();
    assert!(
        fixture
            .runtime
            .graph
            .lock()
            .owner
            .rollback_birth(&birth.permit)
    );
    drop(birth);
    // SAFETY: the hook above has run and released its use of the entry.
    let sibling_entry = unsafe { &mut *sibling_entry };
    sibling_entry.release_birth_waiters().unwrap();
    assert!(!matches!(
        fixture.zone.record(root.id).claim(),
        Claim::Parked { .. }
    ));

    // The woken root reruns its wait and reaps the child.
    let (again, address, words) = capacity.select().unwrap();
    assert_eq!(again, root);
    let mut reap_service = fixture.service();
    let mut waiter = fixture
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
            &mut reap_service,
        )
        .unwrap();
    match waiter.resume_checkpoint(|_| Ok(None)) {
        Ok(NativeResume::Returned(result)) => assert_eq!(result.raw(), child_pid),
        _ => panic!("the released waiter did not reap its child"),
    }
    assert_eq!(reap_service.copies, vec![LinuxWaitStatus::exited(5)]);
}

/// #2095, publication arm: a host requester claims a running native child
/// (OnCpu -> OnCpuRequested, as in #1467) while it parks a blocking `wait4`
/// or a `vfork` suspension. Park admission refusing for that request is
/// contention: the child leaves through its owner checkpoint with its wait
/// retained, never -EAGAIN and never an unsuspended vfork. Busy once, then
/// success: after the host hands the child back, its next owner entry
/// reruns the retained wait, which parks.
#[cfg(test)]
fn host_request_during_child_wait_park(vfork: bool) {
    use carrick_sched_core::{Claim, Handback, HostClaim, ShortLockSpin};
    let capacity = NativeServiceCapacityFixture::new(1);
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let (record, address, words) = capacity.select().unwrap();
    assert_ne!(record, fixture.record);
    assert!(fixture.zone.record(record.id).is_native_owned());
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
            address,
            &words,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
    let grandchild = if vfork {
        None
    } else {
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("fork did not return");
        };
        assert!(result.raw() > 0, "fork result {}", result.raw());
        Some(result.raw())
    };
    // The host requests this exact running child before it parks.
    assert_eq!(
        fixture
            .zone
            .claim_for_host(record, None, Handback::Control, &ShortLockSpin, &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            }),
        HostClaim::El1Held { slot: fixture.slot }
    );
    let outcome = match grandchild {
        Some(pid) => entry.wait4(
            ProcessWaitPid::from_syscall_argument(pid as u64),
            UserVa::new(0x1000),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        ),
        None => entry.fork(ProcessForkChildTid {
            parent: ProcessForkParent::SuspendedUntilExecOrExit,
            ..ProcessForkChildTid::NONE
        }),
    };
    assert!(
        matches!(outcome, LifecycleOutcome::Transferred { .. }),
        "a host request during the park must yield, not return {:?}",
        match outcome {
            LifecycleOutcome::Returned { result, .. } => Some(result.raw()),
            _ => None,
        }
    );
    assert!(entry.take_handoff_receipt().is_some());
    drop(entry);
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    // The native owner, not the host, resumes the retained wait.
    assert_eq!(
        fixture.zone.record(record.id).resume_disposition(),
        carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(
            carrick_sched_core::object_wait::OwnerEntry::Syscall
        )
    );
    assert!(fixture.zone.record(record.id).needs_native_handback());

    // The stopped executor honours the request and hands the record back.
    let mut wanted = alloc::vec::Vec::new();
    fixture
        .zone
        .take_host_wanted(fixture.slot, &mut |wanted_record| {
            wanted.push(wanted_record)
        });
    assert_eq!(wanted.as_slice(), &[record]);
    assert!(fixture.zone.place_native_handback(record).is_some());

    // Its next owner entry reruns the retained wait, which now parks.
    let (again, address, words) = loop {
        let selected = capacity.select().unwrap();
        if selected.0 == record {
            break selected;
        }
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, selected.0.id)
                .is_queued()
        );
    };
    assert_eq!(again, record);
    let mut service = fixture.service();
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            address,
            &words,
            &mut service,
        )
        .unwrap();
    let resumed = entry.resume_checkpoint(|_| Ok(None));
    assert!(
        matches!(resumed, Ok(NativeResume::Left(None))),
        "the retained wait must repark after the handback"
    );
    drop(entry);
    assert!(matches!(
        fixture.zone.record(record.id).claim(),
        Claim::Parked { .. }
    ));
}

#[cfg(test)]
#[test]
fn host_request_during_wait4_park_yields_then_reparks() {
    host_request_during_child_wait_park(false);
}

#[cfg(test)]
#[test]
fn host_request_during_vfork_park_yields_then_reparks() {
    host_request_during_child_wait_park(true);
}

#[cfg(test)]
#[test]
fn wait4_status_owner_wait_retains_zombie_until_release() {
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
            child.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
    }
    let (_, address, saved) = capacity.select().unwrap();
    let handle = service.service_mm_handle(&address).unwrap();
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
    let observed = space
        .notifications(handle.incarnation())
        .unwrap()
        .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    access.raise(space.index());
    // SAFETY: the fixture holds this exact MM gate through enrollment.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    service.child_copy_error = Some(NativeProcessError::OwnerWait(wait));
    {
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
        assert!(
            matches!(
                parent.resume_checkpoint(|_| Ok(None)),
                Ok(NativeResume::Left(None))
            ),
            "owner contention must release execution, never return EFAULT"
        );
    }
    assert!(service.copies.is_empty());
    assert!(fixture.task.service_notice.take().unwrap().is_none());
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    service.child_copy_error = None;
    access.lower(space.index());
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
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
    assert!(matches!(
        parent.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::RetrySyscall
    ));
    assert!(matches!(parent.wait4(
        ProcessWaitPid::from_syscall_argument(u64::MAX), UserVa::new(0x1000),
        LinuxWaitOptions::empty(), UserVa::new(0),
    ), LifecycleOutcome::Returned { result, .. } if result.raw() == i64::from(child_pid)));
    drop(parent);
    assert_eq!(service.copies, vec![LinuxWaitStatus::exited(7)]);
}

#[cfg(test)]
#[test]
fn wait4_rusage_owner_wait_retains_reaped_answer_until_release() {
    let capacity = NativeServiceCapacityFixture::new_with_rusage(1, UserVa::new(0x2000));
    take_signal_copies();
    let fixture = &capacity.fixture;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let (record, address, saved) = capacity.select().unwrap();
    // Non-zero accounting: the retained answer must carry the child's usage.
    let child = fixture
        .registry
        .state
        .lock()
        .members
        .values()
        .find(|member| member.record == record)
        .unwrap()
        .process;
    fixture
        .runtime
        .graph
        .lock()
        .owner
        .task_mut(child)
        .unwrap()
        .native_mut()
        .resources_mut()
        .usage = TaskRusage {
        user_time: Duration::from_micros(1_250_000),
        system_time: Duration::from_micros(2_500_000),
    };
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
            child.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
    }
    let (_, address, saved) = capacity.select().unwrap();
    let handle = service.service_mm_handle(&address).unwrap();
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
    let observed = space
        .notifications(handle.incarnation())
        .unwrap()
        .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    access.raise(space.index());
    // SAFETY: the fixture holds this exact MM gate through enrollment.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    SIGNAL_COPY_ERRORS.with(|errors| {
        errors
            .borrow_mut()
            .push_back(NativeProcessError::OwnerWait(wait))
    });
    {
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
        assert!(
            matches!(
                parent.resume_checkpoint(|_| Ok(None)),
                Ok(NativeResume::Left(None))
            ),
            "owner contention must release execution, never return EFAULT"
        );
    }
    assert_eq!(service.copies, vec![LinuxWaitStatus::exited(7)]);
    assert!(take_signal_copies().is_empty());
    assert!(fixture.task.service_notice.take().unwrap().is_none());
    assert!(fixture.zone.slot(fixture.slot).current().is_none());
    service.child_copy_error = None;
    access.lower(space.index());
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    let saved = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
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
    assert!(matches!(
        parent.resume_checkpoint(|_| Ok(None)).unwrap(),
        NativeResume::Returned(result) if result.raw() == i64::from(child_pid)
    ));
    assert!(matches!(parent.wait4(
        ProcessWaitPid::from_syscall_argument(u64::MAX), UserVa::new(0x1000),
        LinuxWaitOptions::empty(), UserVa::new(0x2000),
    ), LifecycleOutcome::Returned { result, .. } if result.raw() == -10));
    drop(parent);
    assert_eq!(service.copies, vec![LinuxWaitStatus::exited(7)]);
    let copies = take_signal_copies();
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].0, UserVa::new(0x2000));
    use carrick_abi::KernelAbi;
    assert_eq!(
        copies[0].1,
        carrick_abi::LinuxRusage::from_accounting(1_250_000, 2_500_000, 0, 0).abi_bytes()
    );
}

/// #2321: the MM owner releases after the status copy sampled its gate and
/// before the waiter enrolls, so the owner park reports `Changed`. The
/// unconsumed zombie must be rescanned in the same wait; returning the
/// synchronous redispatch from the owned wait continuation is invalid, and
/// from a direct wait4 it leaves the syscall unanswered and the zombie
/// unreaped. `direct` re-executes wait4 on a zombie already exited; otherwise
/// the blocking wait4 continuation resumes through the production checkpoint.
#[cfg(test)]
fn wait4_status_owner_released_before_enrolment(direct: bool) {
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
            child.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
    }
    let (_, address, mut saved) = capacity.select().unwrap();
    let handle = service.service_mm_handle(&address).unwrap();
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
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    let gate_wait = || {
        let observed = space
            .notifications(handle.incarnation())
            .unwrap()
            .observe(carrick_sched_core::spaces::notification::SpaceWaitCause::Gate);
        access.raise(space.index());
        // SAFETY: the receipt names this exact MM and the revision its gate
        // had when the refusal sampled it.
        unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                handle,
                carrick_core_abi::PortalWaitCause::Gate,
                observed.revision(),
            )
        }
    };
    if direct {
        // The blocking wait parks on a held gate, then its release retries
        // the exact wait4 syscall against the still-unreaped zombie.
        let wait = gate_wait();
        STATUS_COPY_ERRORS.with(|errors| {
            errors
                .borrow_mut()
                .push_back(NativeProcessError::OwnerWait(wait))
        });
        {
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
            assert!(matches!(
                parent.resume_checkpoint(|_| Ok(None)),
                Ok(NativeResume::Left(None))
            ));
        }
        assert!(service.copies.is_empty());
        access.lower(space.index());
        assert_eq!(
            fixture.zone.switch_in_full(fixture.slot).unwrap().record,
            fixture.record.id
        );
        saved = unsafe { fixture.runtime.record_binding(fixture.record) }
            .unwrap()
            .words;
    }
    // The holder releases before this waiter can enroll on its gate.
    let wait = gate_wait();
    access.lower(space.index());
    STATUS_COPY_ERRORS.with(|errors| {
        errors
            .borrow_mut()
            .push_back(NativeProcessError::OwnerWait(wait))
    });
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
    if direct {
        assert!(matches!(
            parent.resume_checkpoint(|_| Ok(None)).unwrap(),
            NativeResume::RetrySyscall
        ));
        let outcome = parent.wait4(
            ProcessWaitPid::from_syscall_argument(u64::MAX),
            UserVa::new(0x1000),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        );
        assert!(
            matches!(outcome, LifecycleOutcome::Returned { result, .. } if result.raw() == i64::from(child_pid)),
            "a released owner must rescan the zombie, never redispatch the syscall"
        );
    } else {
        let resumed = parent.resume_checkpoint(|_| Ok(None));
        assert!(
            matches!(resumed, Ok(NativeResume::Returned(result)) if result.raw() == i64::from(child_pid)),
            "a released owner must rescan the zombie, never resume as invalid: {}",
            match resumed {
                Ok(NativeResume::Invalid) => "Invalid",
                Ok(_) => "another resume",
                Err(_) => "run failure",
            }
        );
    }
    assert!(STATUS_COPY_ERRORS.with(|errors| errors.borrow().is_empty()));
    assert!(matches!(parent.wait4(
        ProcessWaitPid::from_syscall_argument(u64::MAX), UserVa::new(0x1000),
        LinuxWaitOptions::empty(), UserVa::new(0),
    ), LifecycleOutcome::Returned { result, .. } if result.raw() == -10));
    drop(parent);
    assert_eq!(service.copies, vec![LinuxWaitStatus::exited(7)]);
}

#[cfg(test)]
#[test]
fn wait4_blocking_status_owner_released_before_enrolment_rescans() {
    wait4_status_owner_released_before_enrolment(false);
}

#[cfg(test)]
#[test]
fn wait4_exited_zombie_status_owner_released_before_enrolment_rescans() {
    wait4_status_owner_released_before_enrolment(true);
}
