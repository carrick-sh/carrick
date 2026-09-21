use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_fatal::carrick_fatal;

use carrick_aarch64::mailbox::{
    AARCH64_SYSCALL_MAILBOX_MAGIC, AARCH64_SYSCALL_MAILBOX_SIZE, AARCH64_SYSCALL_MAILBOX_VERSION,
    Aarch64SyscallMailbox, MailboxProtocolError, MailboxRequestMetadata, MailboxResponseAction,
    MailboxState, validate_request_metadata,
};
use carrick_guest_mem::Aarch64SyscallFrame;
use carrick_hal::threaded::Aarch64SyscallContinuationV1;

pub use carrick_mem::memory::{
    LINUX_SYSCALL_MAILBOX_ARENA_SIZE, LINUX_SYSCALL_MAILBOX_BASE,
    LINUX_SYSCALL_MAILBOX_SLOTS as AARCH64_SYSCALL_MAILBOX_SLOTS,
};

const _: () = assert!(
    AARCH64_SYSCALL_MAILBOX_SIZE * AARCH64_SYSCALL_MAILBOX_SLOTS as u64
        == LINUX_SYSCALL_MAILBOX_ARENA_SIZE
);

pub const HVF_SYSCALL_TRANSPORT_ENV: &str = "CARRICK_HVF_SYSCALL_TRANSPORT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvfSyscallTransport {
    Legacy,
    Mailbox,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {HVF_SYSCALL_TRANSPORT_ENV} value {value:?}; expected `legacy` or `mailbox`")]
pub struct HvfSyscallTransportError {
    value: String,
}

impl HvfSyscallTransport {
    pub const fn raw(self) -> u32 {
        match self {
            Self::Legacy => 0,
            Self::Mailbox => 1,
        }
    }

    pub fn parse(value: Option<&str>) -> Result<Self, HvfSyscallTransportError> {
        match value {
            None | Some("legacy") => Ok(Self::Legacy),
            Some("mailbox") => Ok(Self::Mailbox),
            Some(value) => Err(HvfSyscallTransportError {
                value: value.to_owned(),
            }),
        }
    }

    pub fn from_env() -> Result<Self, HvfSyscallTransportError> {
        let value = std::env::var_os(HVF_SYSCALL_TRANSPORT_ENV);
        match value.as_deref() {
            None => Self::parse(None),
            Some(value) => value.to_str().map_or_else(
                || {
                    Err(HvfSyscallTransportError {
                        value: "<non-utf8>".to_owned(),
                    })
                },
                |value| Self::parse(Some(value)),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxSlotId(u16);

impl MailboxSlotId {
    pub const fn raw(self) -> u16 {
        self.0
    }

    pub const fn guest_address(self) -> u64 {
        LINUX_SYSCALL_MAILBOX_BASE + self.0 as u64 * AARCH64_SYSCALL_MAILBOX_SIZE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailboxSlotError {
    #[error("all AArch64 syscall mailbox slots are in use")]
    Exhausted,
}

#[derive(Debug)]
pub struct MailboxSlotAllocator {
    used: parking_lot::Mutex<[bool; AARCH64_SYSCALL_MAILBOX_SLOTS]>,
}

pub(crate) static MAILBOX_SLOT_CLAIMS_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
thread_local! {
    static THREAD_MAILBOX_SLOT_CLAIMS_TOTAL: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

pub(crate) fn current_thread_mailbox_slot_claims_total() -> u64 {
    THREAD_MAILBOX_SLOT_CLAIMS_TOTAL.get()
}

impl MailboxSlotAllocator {
    pub fn new() -> Self {
        Self {
            used: parking_lot::Mutex::new([false; AARCH64_SYSCALL_MAILBOX_SLOTS]),
        }
    }

    pub fn allocate(self: &Arc<Self>) -> Result<MailboxSlotLease, MailboxSlotError> {
        let mut used = self.used.lock();
        let Some(index) = used.iter().position(|in_use| !*in_use) else {
            return Err(MailboxSlotError::Exhausted);
        };
        used[index] = true;
        MAILBOX_SLOT_CLAIMS_TOTAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        THREAD_MAILBOX_SLOT_CLAIMS_TOTAL
            .set(THREAD_MAILBOX_SLOT_CLAIMS_TOTAL.get().saturating_add(1));
        let id = MailboxSlotId(u16::try_from(index).map_err(|_| MailboxSlotError::Exhausted)?);
        Ok(MailboxSlotLease {
            id,
            allocator: Arc::clone(self),
        })
    }
}

impl Default for MailboxSlotAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct MailboxSlotLease {
    id: MailboxSlotId,
    allocator: Arc<MailboxSlotAllocator>,
}

impl MailboxSlotLease {
    pub const fn id(&self) -> MailboxSlotId {
        self.id
    }
}

impl Drop for MailboxSlotLease {
    fn drop(&mut self) {
        self.allocator.used.lock()[usize::from(self.id.0)] = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxRequest {
    pub frame: Aarch64SyscallFrame,
    pub native_nr: u64,
    pub resume_pc: u64,
    pub spsr: u64,
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub esr: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailboxConsumeError {
    #[error("invalid AArch64 syscall mailbox request: {0:?}")]
    Protocol(MailboxProtocolError),
    #[error("AArch64 syscall HVC arrived without a published mailbox request")]
    MissingRequest,
    #[error("legacy HVF syscall register decode failed: {0}")]
    Legacy(String),
    #[error("AArch64 syscall mailbox binding is already parked")]
    AlreadyParked,
    #[error("AArch64 syscall mailbox binding is not parked")]
    NotParked,
    #[error("AArch64 syscall mailbox binding has no live slot")]
    NoLiveSlot,
}

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn fresh_generation() -> u64 {
    loop {
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        if generation != 0 {
            return generation;
        }
    }
}

#[derive(Debug)]
pub struct MailboxBinding {
    lease: Option<MailboxSlotLease>,
    host: NonNull<Aarch64SyscallMailbox>,
    generation: u64,
    last_sequence: u64,
    transport: HvfSyscallTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxDiagnostics {
    pub generation: u64,
    pub sequence: u64,
    pub state: u32,
    pub response_action: u32,
    pub native_nr: u64,
    pub return_value: u64,
}

// SAFETY: the pointer names a fixed, process-lifetime HVF guest mapping. A
// binding has one logical vCPU owner and moves only with that vCPU to its owning
// host thread; guest/host ownership is synchronized by the mailbox state word.
unsafe impl Send for MailboxBinding {}

/// Original EL0 syscall state to replay after a kick in dormant clock code.
#[derive(Debug)]
pub struct ClockKickRestart {
    pub pc: u64,
    pub pstate: u64,
    pub registers: Vec<(u32, u64)>,
}

impl MailboxBinding {
    /// The owning vCPU must be stopped throughout this operation.
    pub fn force_clock_host_boundary(&mut self) -> Result<(), MailboxConsumeError> {
        if self.lease.is_none() {
            return Err(MailboxConsumeError::NoLiveSlot);
        }
        let mailbox = self.host.as_ptr();
        // SAFETY: an unreleased binding owns this complete slot; stopped vCPU
        // excludes concurrent guest stores, and other executors cannot use it.
        unsafe {
            let generation = core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).generation));
            if generation != self.generation {
                return Err(MailboxConsumeError::Protocol(
                    MailboxProtocolError::StaleGeneration {
                        expected: self.generation,
                        actual: generation,
                    },
                ));
            }
            let flags = core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).flags));
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).flags),
                flags | carrick_aarch64::mailbox::CLOCK_FORCE_HOST_BOUNDARY,
            );
        }
        Ok(())
    }

    /// Normalize every instruction boundary, including the completion tail
    /// after ClockActive was cleared. Merely setting a flag there is too late.
    pub fn clock_kick_restart(
        &mut self,
        pc: u64,
        elr: u64,
        spsr: u64,
        esr: u64,
    ) -> Result<Option<ClockKickRestart>, MailboxConsumeError> {
        self.force_clock_host_boundary()?;
        let layout = carrick_mem::memory::clock_handler_layout();
        let in_handler = (layout.start..layout.end).contains(&pc);
        let in_stub = carrick_mem::memory::is_carrick_el0_clock_stub_va(pc);
        if !in_handler && !in_stub {
            return Ok(None);
        }
        let mailbox = self.host.as_ptr();
        // SAFETY: same stopped-vCPU/exclusive-slot contract as the latch above.
        unsafe {
            let active = self.state().load(Ordering::Acquire) == MailboxState::ClockActive.raw();
            if in_stub && !active {
                return Ok(None);
            }
            let saved = active || pc >= layout.completion;
            let mut registers = Vec::new();
            let (resume_pc, pstate) = if saved {
                let args = core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).args));
                registers.extend(args.into_iter().enumerate().map(|(i, v)| (i as u32, v)));
                registers.extend([
                    (
                        8,
                        core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).x8)),
                    ),
                    (
                        9,
                        core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).clock_x9)),
                    ),
                    (
                        10,
                        core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).clock_x10)),
                    ),
                    (
                        11,
                        core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).clock_x11)),
                    ),
                    (
                        12,
                        core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).clock_x12)),
                    ),
                    (
                        16,
                        core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).resume_x16)),
                    ),
                    (
                        17,
                        core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).resume_x17)),
                    ),
                ]);
                (
                    core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).resume_pc)),
                    core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).spsr)),
                )
            } else {
                // A kicked ordinary data-abort dispatch must continue its
                // fault path; its ELR is not a post-SVC return address.
                if esr >> 26 != 0x15 {
                    return Ok(None);
                }
                for (r, after) in [(16, 4), (17, 8)] {
                    if pc >= layout.start + after {
                        let ptr = if r == 16 {
                            core::ptr::addr_of!((*mailbox).clock_tmp_x16)
                        } else {
                            core::ptr::addr_of!((*mailbox).clock_tmp_x17)
                        };
                        registers.push((r, core::ptr::read_volatile(ptr)));
                    }
                }
                (elr, spsr)
            };
            self.state()
                .store(MailboxState::Idle.raw(), Ordering::Release);
            Ok(Some(ClockKickRestart {
                pc: resume_pc.wrapping_sub(4),
                pstate,
                registers,
            }))
        }
    }

    pub(crate) fn is_released_for_executor_boundary(&self) -> bool {
        self.lease.is_none()
    }
    pub fn diagnostics(&self) -> MailboxDiagnostics {
        let mailbox = self.host.as_ptr();
        // SAFETY: the binding owns a live complete mailbox slot. Diagnostics are
        // sampled only while the vCPU is stopped after a protocol failure.
        unsafe {
            MailboxDiagnostics {
                generation: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).generation)),
                sequence: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).sequence)),
                state: self.state().load(Ordering::Acquire),
                response_action: core::ptr::read_volatile(core::ptr::addr_of!(
                    (*mailbox).response_action
                )),
                native_nr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).native_nr)),
                return_value: core::ptr::read_volatile(core::ptr::addr_of!(
                    (*mailbox).return_value
                )),
            }
        }
    }
    /// Bind a Carrick-owned slot to its fixed host mapping.
    ///
    /// # Safety
    ///
    /// `host` must point to the complete, correctly aligned 256-byte mapping
    /// for `lease.id()` and remain valid until the next `rebind` or drop.
    pub unsafe fn new(
        lease: MailboxSlotLease,
        host: NonNull<Aarch64SyscallMailbox>,
        transport: HvfSyscallTransport,
    ) -> Self {
        let mut binding = Self {
            lease: Some(lease),
            host,
            generation: 0,
            last_sequence: 0,
            transport,
        };
        // SAFETY: upheld by this constructor's caller.
        unsafe { binding.rebind(host, false) };
        binding
    }

    pub fn slot(&self) -> MailboxSlotId {
        let Some(lease) = self.lease.as_ref() else {
            carrick_fatal!(
                "hvpatch::mailbox_authority",
                "mailbox slot identifier accessed without lease on binding: generation={} transport={:?}",
                self.generation,
                self.transport
            );
        };
        lease.id()
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn transport(&self) -> HvfSyscallTransport {
        self.transport
    }

    pub const fn sequence(&self) -> u64 {
        self.last_sequence
    }

    pub(crate) fn host_address(&self) -> usize {
        self.host.as_ptr() as usize
    }

    /// Sample a stopped mailbox backing that may not be the binding's current
    /// host pointer. Used only to enrich a fail-closed transport error.
    ///
    /// # Safety
    ///
    /// `host` must point to a complete live mailbox backing while sampled.
    pub(crate) unsafe fn diagnostics_at(
        host: NonNull<Aarch64SyscallMailbox>,
    ) -> MailboxDiagnostics {
        let mailbox = host.as_ptr();
        // SAFETY: upheld by the caller; the vCPU is stopped at its synchronous
        // HVC, and the acquire state load observes any guest publication.
        unsafe {
            MailboxDiagnostics {
                generation: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).generation)),
                sequence: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).sequence)),
                state: (*mailbox).state.load(Ordering::Acquire),
                response_action: core::ptr::read_volatile(core::ptr::addr_of!(
                    (*mailbox).response_action
                )),
                native_nr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).native_nr)),
                return_value: core::ptr::read_volatile(core::ptr::addr_of!(
                    (*mailbox).return_value
                )),
            }
        }
    }

    fn snapshot_outstanding(&self, state: u32) -> Aarch64SyscallContinuationV1 {
        let mailbox = self.host.as_ptr();
        // SAFETY: callers stop the vCPU or are handling its synchronous exit;
        // acquire-loading `state` before this call makes the guest's complete
        // request publication visible.
        unsafe {
            Aarch64SyscallContinuationV1 {
                sequence: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).sequence)),
                state,
                trap_kind: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).trap_kind)),
                response_action: core::ptr::read_volatile(core::ptr::addr_of!(
                    (*mailbox).response_action
                )),
                flags: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).flags)),
                native_nr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).native_nr)),
                args: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).args)),
                x8: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).x8)),
                resume_pc: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).resume_pc)),
                spsr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).spsr)),
                fp: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).fp)),
                lr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).lr)),
                sp: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).sp)),
                esr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).esr)),
                return_value: core::ptr::read_volatile(core::ptr::addr_of!(
                    (*mailbox).return_value
                )),
                resume_x16: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).resume_x16)),
                resume_x17: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).resume_x17)),
            }
        }
    }

    fn restore_outstanding(&self, parked: Aarch64SyscallContinuationV1) {
        let mailbox = self.host.as_ptr();
        // SAFETY: the binding uniquely owns the complete destination slot and
        // publishes `state` only after every payload word is restored.
        unsafe {
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).sequence),
                parked.sequence,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).trap_kind),
                parked.trap_kind,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).response_action),
                parked.response_action,
            );
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).flags), parked.flags);
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).native_nr),
                parked.native_nr,
            );
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).args), parked.args);
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).x8), parked.x8);
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).resume_pc),
                parked.resume_pc,
            );
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).spsr), parked.spsr);
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).fp), parked.fp);
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).lr), parked.lr);
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).sp), parked.sp);
            self.write_volatile(core::ptr::addr_of_mut!((*mailbox).esr), parked.esr);
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).return_value),
                parked.return_value,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).resume_x16),
                parked.resume_x16,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*mailbox).resume_x17),
                parked.resume_x17,
            );
        }
        self.state().store(parked.state, Ordering::Release);
    }

    pub fn export_task_continuation(
        &self,
    ) -> Result<Option<Aarch64SyscallContinuationV1>, MailboxConsumeError> {
        if self.lease.is_none() {
            return Err(MailboxConsumeError::AlreadyParked);
        }
        let state = self.state().load(Ordering::Acquire);
        if state == MailboxState::Idle.raw() {
            return Ok(None);
        }
        if state != MailboxState::RequestReady.raw() && state != MailboxState::ResponseReady.raw() {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::RequestReady,
                    actual: state,
                },
            ));
        }
        Ok(Some(self.snapshot_outstanding(state)))
    }

    pub fn import_task_continuation(
        &mut self,
        continuation: Aarch64SyscallContinuationV1,
    ) -> Result<(), MailboxConsumeError> {
        if self.lease.is_none() {
            return Err(MailboxConsumeError::AlreadyParked);
        }
        let state = self.state().load(Ordering::Acquire);
        if state != MailboxState::Idle.raw() {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::Idle,
                    actual: state,
                },
            ));
        }
        if continuation.state != MailboxState::RequestReady.raw()
            && continuation.state != MailboxState::ResponseReady.raw()
        {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::RequestReady,
                    actual: continuation.state,
                },
            ));
        }
        self.last_sequence = continuation.sequence;
        self.restore_outstanding(continuation);
        Ok(())
    }

    pub fn take_task_continuation_for_executor_switch(
        &mut self,
    ) -> Result<Option<Aarch64SyscallContinuationV1>, MailboxConsumeError> {
        if self.lease.is_none() {
            return Err(MailboxConsumeError::AlreadyParked);
        }
        let continuation = self.export_task_continuation()?;
        self.state()
            .store(MailboxState::Idle.raw(), Ordering::Release);
        self.last_sequence = 0;
        Ok(continuation)
    }

    /// Snapshot the outstanding response vehicle and release this binding's
    /// finite arena slot while its vCPU is destroyed for an M:N blocking wait.
    /// The guest is stopped immediately after the HVC, so only the continuation
    /// payload needs to survive; the next vCPU receives a freshly generated
    /// binding and resumes the same EL1 continuation from its new `SP_EL1`.
    pub fn release_for_reclaim(&mut self) -> Result<(), MailboxConsumeError> {
        if self.lease.is_none() {
            return Err(MailboxConsumeError::AlreadyParked);
        }
        self.export_task_continuation()?.ok_or_else(|| {
            MailboxConsumeError::Protocol(MailboxProtocolError::UnexpectedState {
                expected: MailboxState::RequestReady,
                actual: MailboxState::Idle.raw(),
            })
        })?;
        drop(self.lease.take());
        self.last_sequence = 0;
        Ok(())
    }

    /// Release the executor-local mailbox slot for the zero-instruction
    /// initial-runner handoff. Unlike blocking reclaim, this path accepts only
    /// `Idle`: it never invents a syscall request or continuation authority.
    pub fn release_idle_for_initial_handoff(&mut self) -> Result<(), MailboxConsumeError> {
        if self.lease.is_none() {
            return Err(MailboxConsumeError::AlreadyParked);
        }
        let state = self.state().load(Ordering::Acquire);
        if state != MailboxState::Idle.raw() {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::Idle,
                    actual: state,
                },
            ));
        }
        drop(self.lease.take());
        self.last_sequence = 0;
        Ok(())
    }

    /// Attach a newly allocated arena slot after reclaim and restore the exact
    /// outstanding continuation captured by [`Self::release_for_reclaim`].
    ///
    /// # Safety
    ///
    /// `host` must name the complete, live mapping for `lease.id()` and remain
    /// valid for this binding's lifetime.
    pub unsafe fn reacquire_after_reclaim(
        &mut self,
        lease: MailboxSlotLease,
        host: NonNull<Aarch64SyscallMailbox>,
        continuation: Option<Aarch64SyscallContinuationV1>,
    ) -> Result<(), MailboxConsumeError> {
        if self.lease.is_some() {
            return Err(MailboxConsumeError::AlreadyParked);
        }
        self.lease = Some(lease);
        // SAFETY: the caller supplies the complete uniquely leased slot.
        unsafe { self.rebind(host, false) };
        if let Some(continuation) = continuation {
            self.import_task_continuation(continuation)?;
        }
        Ok(())
    }

    /// Refresh the host pointer and generation after a VM/vCPU rebuild.
    ///
    /// # Safety
    ///
    /// `host` must satisfy the same mapping requirements as [`Self::new`].
    pub unsafe fn rebind(
        &mut self,
        host: NonNull<Aarch64SyscallMailbox>,
        preserve_outstanding: bool,
    ) {
        let preserved = preserve_outstanding
            .then(|| {
                let state = self.state().load(Ordering::Acquire);
                (state == MailboxState::RequestReady.raw()
                    || state == MailboxState::ResponseReady.raw())
                .then(|| self.snapshot_outstanding(state))
            })
            .flatten();
        self.host = host;
        self.generation = fresh_generation();
        // SAFETY: the binding owns this mapped mailbox slot.
        unsafe {
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).magic),
                AARCH64_SYSCALL_MAILBOX_MAGIC,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).version),
                AARCH64_SYSCALL_MAILBOX_VERSION,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).size),
                AARCH64_SYSCALL_MAILBOX_SIZE as u32,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).generation),
                self.generation,
            );
            if preserved.is_none() {
                self.write_volatile(core::ptr::addr_of_mut!((*self.host.as_ptr()).sequence), 0);
                self.write_volatile(core::ptr::addr_of_mut!((*self.host.as_ptr()).flags), 0);
            }
        }
        if let Some(parked) = preserved {
            self.restore_outstanding(parked);
        } else {
            self.last_sequence = 0;
            self.state()
                .store(MailboxState::Idle.raw(), Ordering::Release);
        }
    }

    /// Follow a stage-1 COW relocation of this slot without modifying the
    /// already-published mailbox protocol state in the replacement backing.
    ///
    /// # Safety
    ///
    /// `host` must point to the complete replacement backing for this binding's
    /// currently leased guest slot and remain valid until the next relocation,
    /// rebind, or drop.
    pub unsafe fn relocate_after_cow(&mut self, host: NonNull<Aarch64SyscallMailbox>) {
        self.host = host;
    }

    pub fn take_request(&mut self) -> Result<Option<MailboxRequest>, MailboxConsumeError> {
        let state = self.state().load(Ordering::Acquire);
        if state == MailboxState::Idle.raw() {
            return Ok(None);
        }

        // SAFETY: acquire ownership above makes the guest-published payload
        // visible, and all fields stay inside this binding's mapped slot.
        let (metadata, request) = unsafe {
            let mailbox = self.host.as_ptr();
            let metadata = MailboxRequestMetadata {
                magic: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).magic)),
                version: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).version)),
                size: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).size)),
                generation: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).generation)),
                sequence: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).sequence)),
                state,
                trap_kind: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).trap_kind)),
            };
            let args = core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).args));
            let request = MailboxRequest {
                frame: Aarch64SyscallFrame {
                    x0: args[0],
                    x1: args[1],
                    x2: args[2],
                    x3: args[3],
                    x4: args[4],
                    x5: args[5],
                    x8: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).x8)),
                },
                native_nr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).native_nr)),
                resume_pc: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).resume_pc)),
                spsr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).spsr)),
                fp: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).fp)),
                lr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).lr)),
                sp: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).sp)),
                esr: core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).esr)),
            };
            (metadata, request)
        };
        validate_request_metadata(metadata, self.generation, self.last_sequence)
            .map_err(MailboxConsumeError::Protocol)?;
        self.last_sequence = metadata.sequence;
        // Reaching validated host dispatch satisfies the latched boundary.
        unsafe {
            let flags = core::ptr::read_volatile(core::ptr::addr_of!((*self.host.as_ptr()).flags));
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).flags),
                flags & !carrick_aarch64::mailbox::CLOCK_FORCE_HOST_BOUNDARY,
            );
        }
        Ok(Some(request))
    }

    /// Decode an HVC2 syscall from the selected internal transport. Both modes
    /// validate and consume the mailbox publication; diagnostic legacy mode then
    /// deliberately obtains the frame through the supplied register reader.
    pub fn decode_request<F>(
        &mut self,
        legacy_decode: F,
    ) -> Result<MailboxRequest, MailboxConsumeError>
    where
        F: FnOnce() -> Result<MailboxRequest, MailboxConsumeError>,
    {
        let request = self
            .take_request()?
            .ok_or(MailboxConsumeError::MissingRequest)?;
        match self.transport {
            HvfSyscallTransport::Mailbox => Ok(request),
            HvfSyscallTransport::Legacy => legacy_decode(),
        }
    }

    pub fn publish_normal_return(&mut self, value: i64) -> Result<(), MailboxConsumeError> {
        self.require_request_ready()?;
        // SAFETY: the host owns RequestReady and publishes state only after both
        // payload stores complete.
        unsafe {
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).return_value),
                value as u64,
            );
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).response_action),
                MailboxResponseAction::NormalReturn.raw(),
            );
        }
        self.state()
            .store(MailboxState::ResponseReady.raw(), Ordering::Release);
        Ok(())
    }

    /// Read a normal return that this exact binding has published but the EL1
    /// trampoline has not consumed. This is the authoritative x0 source when a
    /// signal replaces a mailbox return before `eret` reaches EL0.
    pub fn pending_normal_return(&self) -> Result<Option<i64>, MailboxConsumeError> {
        if self.lease.is_none() {
            return Err(MailboxConsumeError::NoLiveSlot);
        }
        let state = self.state().load(Ordering::Acquire);
        match MailboxState::try_from(state) {
            Ok(MailboxState::ResponseReady) => {}
            Ok(MailboxState::Idle | MailboxState::RequestReady | MailboxState::ClockActive) => {
                return Ok(None);
            }
            Err(unknown) => {
                return Err(MailboxConsumeError::Protocol(
                    MailboxProtocolError::UnexpectedState {
                        expected: MailboxState::ResponseReady,
                        actual: unknown.0,
                    },
                ));
            }
        }
        // SAFETY: the acquire above observes the host-published response and
        // this binding owns the mapped slot for its entire lifetime.
        let (magic, version, size, generation, sequence, action, value) = unsafe {
            let mailbox = self.host.as_ptr();
            (
                core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).magic)),
                core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).version)),
                core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).size)),
                core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).generation)),
                core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).sequence)),
                core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).response_action)),
                core::ptr::read_volatile(core::ptr::addr_of!((*mailbox).return_value)),
            )
        };
        if magic != AARCH64_SYSCALL_MAILBOX_MAGIC {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::WrongMagic { actual: magic },
            ));
        }
        if version != AARCH64_SYSCALL_MAILBOX_VERSION {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::WrongVersion { actual: version },
            ));
        }
        if size != AARCH64_SYSCALL_MAILBOX_SIZE as u32 {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::WrongSize { actual: size },
            ));
        }
        if generation != self.generation {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::StaleGeneration {
                    expected: self.generation,
                    actual: generation,
                },
            ));
        }
        if sequence != self.last_sequence {
            return Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::ResponseSequenceMismatch {
                    expected: self.last_sequence,
                    actual: sequence,
                },
            ));
        }
        match MailboxResponseAction::try_from(action) {
            Ok(MailboxResponseAction::NormalReturn) => Ok(Some(value as i64)),
            Ok(MailboxResponseAction::RegistersPrepared) => Ok(None),
            Err(unknown) => Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::UnknownResponseAction(unknown.0),
            )),
        }
    }

    pub fn publish_registers_prepared(&mut self) -> Result<(), MailboxConsumeError> {
        self.require_request_ready()?;
        // SAFETY: the host owns RequestReady and publishes state only after the
        // response action store completes. return_value is intentionally untouched.
        unsafe {
            self.write_volatile(
                core::ptr::addr_of_mut!((*self.host.as_ptr()).response_action),
                MailboxResponseAction::RegistersPrepared.raw(),
            );
        }
        self.state()
            .store(MailboxState::ResponseReady.raw(), Ordering::Release);
        Ok(())
    }

    /// Mark an outstanding syscall response as register-prepared after the host
    /// has explicitly replaced the resume context (signal injection/sigreturn).
    /// Internal EL1 maintenance must not call this: it re-enters the same vCPU
    /// while the original syscall request is still awaiting its ordinary result.
    pub fn publish_register_resume_if_outstanding(&mut self) -> Result<(), MailboxConsumeError> {
        match MailboxState::try_from(self.state().load(Ordering::Acquire)) {
            Ok(MailboxState::RequestReady | MailboxState::ResponseReady) => {
                // SAFETY: the vCPU is stopped and the host owns both response
                // states. Prepared intentionally supersedes a normal payload when
                // signal delivery replaces the live return context.
                unsafe {
                    self.write_volatile(
                        core::ptr::addr_of_mut!((*self.host.as_ptr()).response_action),
                        MailboxResponseAction::RegistersPrepared.raw(),
                    );
                }
                self.state()
                    .store(MailboxState::ResponseReady.raw(), Ordering::Release);
                Ok(())
            }
            Ok(MailboxState::Idle) => Ok(()),
            Ok(MailboxState::ClockActive) => Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::RequestReady,
                    actual: MailboxState::ClockActive.raw(),
                },
            )),
            Err(unknown) => Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::RequestReady,
                    actual: unknown.0,
                },
            )),
        }
    }

    fn require_request_ready(&self) -> Result<(), MailboxConsumeError> {
        let actual = self.state().load(Ordering::Acquire);
        if actual == MailboxState::RequestReady.raw() {
            return Ok(());
        }
        Err(MailboxConsumeError::Protocol(
            MailboxProtocolError::UnexpectedState {
                expected: MailboxState::RequestReady,
                actual,
            },
        ))
    }

    fn state(&self) -> &std::sync::atomic::AtomicU32 {
        // SAFETY: `host` is guaranteed to point at a live complete mailbox for
        // this binding, and `state` is naturally aligned by the wire layout.
        unsafe { &(*self.host.as_ptr()).state }
    }

    unsafe fn write_volatile<T>(&self, pointer: *mut T, value: T) {
        // SAFETY: every caller constructs `pointer` from this binding's live
        // mailbox and names a field wholly contained in the slot.
        unsafe { core::ptr::write_volatile(pointer, value) };
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::NonNull;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use carrick_aarch64::mailbox::{
        AARCH64_SYSCALL_MAILBOX_MAGIC, AARCH64_SYSCALL_MAILBOX_SIZE,
        AARCH64_SYSCALL_MAILBOX_VERSION, Aarch64SyscallMailbox, MailboxResponseAction,
        MailboxState, MailboxTrapKind,
    };

    use super::*;

    fn binding() -> (MailboxBinding, Box<Aarch64SyscallMailbox>) {
        let allocator = Arc::new(MailboxSlotAllocator::new());
        let lease = allocator.allocate().expect("slot");
        let mut mailbox = Box::new(Aarch64SyscallMailbox {
            magic: 0,
            version: 0,
            size: 0,
            generation: 0,
            sequence: 0,
            state: std::sync::atomic::AtomicU32::new(0),
            trap_kind: 0,
            response_action: 0,
            flags: 0,
            native_nr: 0,
            args: [0; 6],
            x8: 0,
            resume_pc: 0,
            spsr: 0,
            fp: 0,
            lr: 0,
            sp: 0,
            esr: 0,
            return_value: 0,
            resume_x16: 0,
            resume_x17: 0,
            clock_x9: 0,
            clock_x10: 0,
            clock_x11: 0,
            clock_x12: 0,
            clock_tmp_x16: 0,
            clock_tmp_x17: 0,
            reserved: [0; 24],
        });
        let pointer = NonNull::from(mailbox.as_mut());
        let binding = unsafe { MailboxBinding::new(lease, pointer, HvfSyscallTransport::Mailbox) };
        (binding, mailbox)
    }

    #[test]
    fn kick_normalization_recovers_pre_active_scratch_registers() {
        let (mut binding, mut mailbox) = binding();
        mailbox.clock_tmp_x16 = 0x1616;
        mailbox.clock_tmp_x17 = 0x1717;
        let layout = carrick_mem::memory::clock_handler_layout();
        let restart = binding
            .clock_kick_restart(layout.start + 8, 0x4004, 0xA0000000, 0x15 << 26)
            .expect("normalize")
            .expect("restart");
        assert_eq!((restart.pc, restart.pstate), (0x4000, 0xA0000000));
        assert_eq!(restart.registers, vec![(16, 0x1616), (17, 0x1717)]);
        assert_eq!(
            mailbox.flags & carrick_aarch64::mailbox::CLOCK_FORCE_HOST_BOUNDARY,
            1
        );
    }

    #[test]
    fn kick_normalization_recovers_active_stub_and_cleared_completion_tail() {
        for (pc, state) in [
            (
                carrick_mem::memory::LINUX_EL0_CLOCK_STUB_BASE,
                MailboxState::ClockActive,
            ),
            (
                carrick_mem::memory::clock_handler_layout().end - 4,
                MailboxState::Idle,
            ),
        ] {
            let (mut binding, mut mailbox) = binding();
            mailbox.state.store(state.raw(), Ordering::Release);
            mailbox.resume_pc = 0x8004;
            mailbox.spsr = 0x60000000;
            mailbox.args = [1, 2, 3, 4, 5, 6];
            mailbox.x8 = 113;
            mailbox.clock_x9 = 9;
            mailbox.clock_x10 = 10;
            mailbox.clock_x11 = 11;
            mailbox.clock_x12 = 12;
            mailbox.resume_x16 = 16;
            mailbox.resume_x17 = 17;
            let restart = binding
                .clock_kick_restart(pc, 0xBAD, 0xBAD, 0xBAD)
                .expect("normalize")
                .expect("restart");
            assert_eq!((restart.pc, restart.pstate), (0x8000, 0x60000000));
            assert_eq!(
                restart.registers,
                vec![
                    (0, 1),
                    (1, 2),
                    (2, 3),
                    (3, 4),
                    (4, 5),
                    (5, 6),
                    (8, 113),
                    (9, 9),
                    (10, 10),
                    (11, 11),
                    (12, 12),
                    (16, 16),
                    (17, 17)
                ]
            );
            assert_eq!(
                mailbox.state.load(Ordering::Acquire),
                MailboxState::Idle.raw()
            );
            assert_eq!(mailbox.flags, 1);
        }
    }

    #[test]
    fn unowned_stub_and_non_svc_entry_do_not_restore_stale_frame() {
        let (mut binding, _mailbox) = binding();
        assert!(
            binding
                .clock_kick_restart(
                    carrick_mem::memory::LINUX_EL0_CLOCK_STUB_BASE,
                    0xBAD,
                    0xBAD,
                    0xBAD
                )
                .expect("stub")
                .is_none()
        );
        assert!(
            binding
                .clock_kick_restart(
                    carrick_mem::memory::clock_handler_layout().start,
                    0xBAD,
                    0xBAD,
                    0x24 << 26
                )
                .expect("fault")
                .is_none()
        );
    }

    #[test]
    fn kick_latch_rejects_stale_generation_and_preserves_other_flags() {
        let (mut binding, mut mailbox) = binding();
        mailbox.flags = 0x80;
        binding.force_clock_host_boundary().expect("latch");
        assert_eq!(mailbox.flags, 0x81);
        mailbox.generation = mailbox.generation.wrapping_add(1);
        assert!(binding.force_clock_host_boundary().is_err());
    }

    fn publish_valid_request(binding: &MailboxBinding, mailbox: &mut Aarch64SyscallMailbox) {
        mailbox.sequence = 1;
        mailbox.trap_kind = MailboxTrapKind::Syscall.raw();
        mailbox.native_nr = 64;
        mailbox.args = [10, 11, 12, 13, 14, 15];
        mailbox.x8 = 64;
        mailbox.resume_pc = 0x1234;
        mailbox.spsr = 0x3c0;
        mailbox.fp = 0x29;
        mailbox.lr = 0x30;
        mailbox.sp = 0x8000;
        mailbox.esr = 0x15 << 26;
        mailbox
            .state
            .store(MailboxState::RequestReady.raw(), Ordering::Release);
        assert_eq!(mailbox.generation, binding.generation());
    }

    #[test]
    fn clean_destination_completes_exported_task_continuation() {
        let (mut source, mut source_mailbox) = binding();
        publish_valid_request(&source, &mut source_mailbox);
        source.take_request().unwrap().expect("source request");
        let continuation = source
            .export_task_continuation()
            .unwrap()
            .expect("typed task continuation");

        let (mut destination, destination_mailbox) = binding();
        assert_eq!(destination.diagnostics().state, MailboxState::Idle.raw());
        destination
            .import_task_continuation(continuation)
            .expect("restore into clean destination mailbox");
        destination.publish_normal_return(0x1234).unwrap();
        assert_eq!(
            destination_mailbox.response_action,
            MailboxResponseAction::NormalReturn.raw()
        );
        assert_eq!(destination_mailbox.return_value, 0x1234);
        assert_eq!(
            destination_mailbox.state.load(Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );
    }

    #[test]
    fn allocator_exhaustion_and_reuse_are_deterministic() {
        let allocator = Arc::new(MailboxSlotAllocator::new());
        let mut leases = Vec::new();
        for expected in 0..AARCH64_SYSCALL_MAILBOX_SLOTS {
            let lease = allocator.allocate().expect("available slot");
            assert_eq!(usize::from(lease.id().raw()), expected);
            assert_eq!(
                lease.id().guest_address(),
                LINUX_SYSCALL_MAILBOX_BASE + expected as u64 * AARCH64_SYSCALL_MAILBOX_SIZE
            );
            assert!(
                lease.id().guest_address() + AARCH64_SYSCALL_MAILBOX_SIZE
                    <= LINUX_SYSCALL_MAILBOX_BASE + LINUX_SYSCALL_MAILBOX_ARENA_SIZE
            );
            leases.push(lease);
        }
        assert!(matches!(
            allocator.allocate(),
            Err(MailboxSlotError::Exhausted)
        ));
        drop(leases.remove(17));
        assert_eq!(allocator.allocate().expect("reused slot").id().raw(), 17);
    }

    #[test]
    fn binding_rebind_changes_generation_and_skips_zero() {
        let (mut binding, mut mailbox) = binding();
        let first = binding.generation();
        let pointer = NonNull::from(mailbox.as_mut());
        unsafe { binding.rebind(pointer, false) };
        assert_ne!(binding.generation(), 0);
        assert_ne!(binding.generation(), first);
        assert_eq!(mailbox.generation, binding.generation());
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::Idle.raw()
        );
    }

    #[test]
    fn rebind_preserves_an_inflight_request_under_the_new_generation() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        let before = binding.generation();
        let pointer = NonNull::from(mailbox.as_mut());
        unsafe { binding.rebind(pointer, true) };

        assert_ne!(binding.generation(), before);
        assert_eq!(mailbox.generation, binding.generation());
        assert_eq!(mailbox.sequence, 1);
        assert_eq!(mailbox.x8, 64);
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::RequestReady.raw()
        );
        assert!(binding.take_request().expect("valid request").is_some());
    }

    #[test]
    fn rebind_moves_an_inflight_request_to_a_rebuilt_mailbox_backing() {
        let (mut binding, mut old_mailbox) = binding();
        publish_valid_request(&binding, &mut old_mailbox);
        let mut rebuilt_mailbox = Box::new(Aarch64SyscallMailbox {
            magic: 0,
            version: 0,
            size: 0,
            generation: 0,
            sequence: 0,
            state: std::sync::atomic::AtomicU32::new(0),
            trap_kind: 0,
            response_action: 0,
            flags: 0,
            native_nr: 0,
            args: [0; 6],
            x8: 0,
            resume_pc: 0,
            spsr: 0,
            fp: 0,
            lr: 0,
            sp: 0,
            esr: 0,
            return_value: 0,
            resume_x16: 0,
            resume_x17: 0,
            clock_x9: 0,
            clock_x10: 0,
            clock_x11: 0,
            clock_x12: 0,
            clock_tmp_x16: 0,
            clock_tmp_x17: 0,
            reserved: [0; 24],
        });
        let rebuilt_pointer = NonNull::from(rebuilt_mailbox.as_mut());

        unsafe { binding.rebind(rebuilt_pointer, true) };

        assert_eq!(
            rebuilt_mailbox.state.load(Ordering::Acquire),
            MailboxState::RequestReady.raw(),
            "fork/reclaim rebuild must move the request instead of sampling the fresh zero backing",
        );
        assert_eq!(rebuilt_mailbox.sequence, 1);
        assert_eq!(rebuilt_mailbox.trap_kind, MailboxTrapKind::Syscall.raw());
        assert_eq!(rebuilt_mailbox.native_nr, 64);
        assert_eq!(rebuilt_mailbox.args, [10, 11, 12, 13, 14, 15]);
        assert_eq!(rebuilt_mailbox.x8, 64);
        assert_eq!(rebuilt_mailbox.resume_pc, 0x1234);
    }

    #[test]
    fn cow_relocation_follows_the_guest_published_replacement_without_reset() {
        let (mut binding, old_mailbox) = binding();
        let mut cow_replacement = Box::new(Aarch64SyscallMailbox {
            magic: old_mailbox.magic,
            version: old_mailbox.version,
            size: old_mailbox.size,
            generation: old_mailbox.generation,
            sequence: old_mailbox.sequence,
            state: std::sync::atomic::AtomicU32::new(old_mailbox.state.load(Ordering::Acquire)),
            trap_kind: old_mailbox.trap_kind,
            response_action: old_mailbox.response_action,
            flags: old_mailbox.flags,
            native_nr: old_mailbox.native_nr,
            args: old_mailbox.args,
            x8: old_mailbox.x8,
            resume_pc: old_mailbox.resume_pc,
            spsr: old_mailbox.spsr,
            fp: old_mailbox.fp,
            lr: old_mailbox.lr,
            sp: old_mailbox.sp,
            esr: old_mailbox.esr,
            return_value: old_mailbox.return_value,
            resume_x16: old_mailbox.resume_x16,
            resume_x17: old_mailbox.resume_x17,
            clock_x9: old_mailbox.clock_x9,
            clock_x10: old_mailbox.clock_x10,
            clock_x11: old_mailbox.clock_x11,
            clock_x12: old_mailbox.clock_x12,
            clock_tmp_x16: old_mailbox.clock_tmp_x16,
            clock_tmp_x17: old_mailbox.clock_tmp_x17,
            reserved: old_mailbox.reserved,
        });
        publish_valid_request(&binding, &mut cow_replacement);
        let generation = binding.generation();
        let replacement_pointer = NonNull::from(cow_replacement.as_mut());

        unsafe { binding.relocate_after_cow(replacement_pointer) };

        assert_eq!(binding.generation(), generation);
        assert_eq!(cow_replacement.generation, generation);
        assert_eq!(cow_replacement.sequence, 1);
        assert_eq!(
            cow_replacement.state.load(Ordering::Acquire),
            MailboxState::RequestReady.raw()
        );
        let request = binding
            .take_request()
            .expect("valid relocated protocol")
            .expect("guest-published replacement request");
        assert_eq!(request.native_nr, 64);
        assert_eq!(request.frame.x0, 10);
        assert_eq!(request.resume_pc, 0x1234);
    }

    #[test]
    fn rebind_preserves_an_inflight_response_for_vector_continuation() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        binding.take_request().expect("protocol").expect("request");
        binding.publish_normal_return(77).expect("response");
        let sequence = mailbox.sequence;
        let before = binding.generation();
        let pointer = NonNull::from(mailbox.as_mut());

        unsafe { binding.rebind(pointer, true) };

        assert_ne!(binding.generation(), before);
        assert_eq!(mailbox.generation, binding.generation());
        assert_eq!(mailbox.sequence, sequence);
        assert_eq!(mailbox.return_value, 77);
        assert_eq!(
            mailbox.response_action,
            MailboxResponseAction::NormalReturn.raw()
        );
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );
    }

    #[test]
    fn reclaim_releases_slot_and_moves_outstanding_request_to_a_new_slot() {
        let allocator = Arc::new(MailboxSlotAllocator::new());
        let lease = allocator.allocate().expect("initial slot");
        let mut old_mailbox = Box::new(Aarch64SyscallMailbox {
            magic: 0,
            version: 0,
            size: 0,
            generation: 0,
            sequence: 0,
            state: std::sync::atomic::AtomicU32::new(0),
            trap_kind: 0,
            response_action: 0,
            flags: 0,
            native_nr: 0,
            args: [0; 6],
            x8: 0,
            resume_pc: 0,
            spsr: 0,
            fp: 0,
            lr: 0,
            sp: 0,
            esr: 0,
            return_value: 0,
            resume_x16: 0,
            resume_x17: 0,
            clock_x9: 0,
            clock_x10: 0,
            clock_x11: 0,
            clock_x12: 0,
            clock_tmp_x16: 0,
            clock_tmp_x17: 0,
            reserved: [0; 24],
        });
        let old_pointer = NonNull::from(old_mailbox.as_mut());
        let mut binding =
            unsafe { MailboxBinding::new(lease, old_pointer, HvfSyscallTransport::Mailbox) };
        assert!(!binding.is_released_for_executor_boundary());
        publish_valid_request(&binding, &mut old_mailbox);
        binding.take_request().expect("protocol").expect("request");

        let continuation = binding
            .export_task_continuation()
            .unwrap()
            .expect("task continuation");
        binding.release_for_reclaim().expect("park mailbox");
        assert!(binding.is_released_for_executor_boundary());
        assert_eq!(binding.sequence(), 0, "source retains no task sequence");
        assert!(matches!(
            binding.export_task_continuation(),
            Err(MailboxConsumeError::AlreadyParked)
        ));
        let occupier = allocator.allocate().expect("park released old slot");
        assert_eq!(occupier.id().raw(), 0);
        let resumed_lease = allocator.allocate().expect("resume slot");
        assert_eq!(resumed_lease.id().raw(), 1);
        let mut resumed_mailbox = Box::new(Aarch64SyscallMailbox {
            magic: 0,
            version: 0,
            size: 0,
            generation: 0,
            sequence: 0,
            state: std::sync::atomic::AtomicU32::new(0),
            trap_kind: 0,
            response_action: 0,
            flags: 0,
            native_nr: 0,
            args: [0; 6],
            x8: 0,
            resume_pc: 0,
            spsr: 0,
            fp: 0,
            lr: 0,
            sp: 0,
            esr: 0,
            return_value: 0,
            resume_x16: 0,
            resume_x17: 0,
            clock_x9: 0,
            clock_x10: 0,
            clock_x11: 0,
            clock_x12: 0,
            clock_tmp_x16: 0,
            clock_tmp_x17: 0,
            reserved: [0; 24],
        });
        let resumed_pointer = NonNull::from(resumed_mailbox.as_mut());
        unsafe {
            binding.reacquire_after_reclaim(resumed_lease, resumed_pointer, Some(continuation))
        }
        .expect("move outstanding request");
        assert!(!binding.is_released_for_executor_boundary());

        assert_eq!(binding.slot().raw(), 1);
        assert_eq!(resumed_mailbox.sequence, 1);
        assert_eq!(binding.sequence(), 1);
        assert_eq!(
            resumed_mailbox.state.load(Ordering::Acquire),
            MailboxState::RequestReady.raw()
        );
        binding.publish_normal_return(77).expect("response");
        assert_eq!(resumed_mailbox.return_value, 77);
        assert_eq!(
            resumed_mailbox.state.load(Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );
    }

    #[test]
    fn valid_request_is_acquired_once_and_decoded_without_registers() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        let request = binding
            .take_request()
            .expect("valid protocol")
            .expect("request");
        assert_eq!(request.frame.x8, 64);
        assert_eq!(
            [
                request.frame.x0,
                request.frame.x1,
                request.frame.x2,
                request.frame.x3,
                request.frame.x4,
                request.frame.x5,
            ],
            [10, 11, 12, 13, 14, 15]
        );
        assert_eq!(request.resume_pc, 0x1234);
        assert!(matches!(
            binding.take_request(),
            Err(MailboxConsumeError::Protocol(
                carrick_aarch64::mailbox::MailboxProtocolError::NonIncreasingSequence { .. }
            ))
        ));
    }

    #[test]
    fn malformed_or_partial_publications_fail_closed() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        mailbox.magic = 0;
        assert!(matches!(
            binding.take_request(),
            Err(MailboxConsumeError::Protocol(
                carrick_aarch64::mailbox::MailboxProtocolError::WrongMagic { .. }
            ))
        ));

        mailbox.magic = AARCH64_SYSCALL_MAILBOX_MAGIC;
        mailbox.version = AARCH64_SYSCALL_MAILBOX_VERSION;
        mailbox.size = AARCH64_SYSCALL_MAILBOX_SIZE as u32;
        mailbox.generation = binding.generation().wrapping_add(1);
        assert!(matches!(
            binding.take_request(),
            Err(MailboxConsumeError::Protocol(
                carrick_aarch64::mailbox::MailboxProtocolError::StaleGeneration { .. }
            ))
        ));

        mailbox.generation = binding.generation();
        mailbox.trap_kind = 99;
        assert!(matches!(
            binding.take_request(),
            Err(MailboxConsumeError::Protocol(
                carrick_aarch64::mailbox::MailboxProtocolError::UnknownTrapKind(99)
            ))
        ));
    }

    #[test]
    fn responses_publish_payload_before_ownership() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        binding.take_request().expect("protocol").expect("request");
        binding.publish_normal_return(-9).expect("normal response");
        assert_eq!(mailbox.return_value, (-9_i64) as u64);
        assert_eq!(
            mailbox.response_action,
            MailboxResponseAction::NormalReturn.raw()
        );
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );

        mailbox.return_value = 0xfeed_face;
        mailbox
            .state
            .store(MailboxState::RequestReady.raw(), Ordering::Release);
        binding
            .publish_registers_prepared()
            .expect("prepared response");
        assert_eq!(mailbox.return_value, 0xfeed_face);
        assert_eq!(
            mailbox.response_action,
            MailboxResponseAction::RegistersPrepared.raw()
        );
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );
    }

    #[test]
    fn transport_parser_is_explicit_and_defaults_to_legacy() {
        assert_eq!(
            HvfSyscallTransport::parse(None).expect("default"),
            HvfSyscallTransport::Legacy
        );
        assert_eq!(
            HvfSyscallTransport::parse(Some("mailbox")).expect("mailbox"),
            HvfSyscallTransport::Mailbox
        );
        assert_eq!(
            HvfSyscallTransport::parse(Some("legacy")).expect("legacy"),
            HvfSyscallTransport::Legacy
        );
        let error = HvfSyscallTransport::parse(Some("auto")).expect_err("invalid value");
        assert!(error.to_string().contains("CARRICK_HVF_SYSCALL_TRANSPORT"));
    }

    #[test]
    fn mailbox_decode_never_invokes_legacy_register_reader() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        let mut register_reads = 0;
        let request = binding
            .decode_request(|| {
                register_reads += 1;
                Err(MailboxConsumeError::MissingRequest)
            })
            .expect("mailbox request");
        assert_eq!(request.frame.x8, 64);
        assert_eq!(register_reads, 0);
    }

    #[test]
    fn legacy_decode_validates_mailbox_then_invokes_register_reader() {
        let allocator = Arc::new(MailboxSlotAllocator::new());
        let lease = allocator.allocate().expect("slot");
        let mut mailbox = Box::new(Aarch64SyscallMailbox {
            magic: 0,
            version: 0,
            size: 0,
            generation: 0,
            sequence: 0,
            state: std::sync::atomic::AtomicU32::new(0),
            trap_kind: 0,
            response_action: 0,
            flags: 0,
            native_nr: 0,
            args: [0; 6],
            x8: 0,
            resume_pc: 0,
            spsr: 0,
            fp: 0,
            lr: 0,
            sp: 0,
            esr: 0,
            return_value: 0,
            resume_x16: 0,
            resume_x17: 0,
            clock_x9: 0,
            clock_x10: 0,
            clock_x11: 0,
            clock_x12: 0,
            clock_tmp_x16: 0,
            clock_tmp_x17: 0,
            reserved: [0; 24],
        });
        let pointer = NonNull::from(mailbox.as_mut());
        let mut binding =
            unsafe { MailboxBinding::new(lease, pointer, HvfSyscallTransport::Legacy) };
        publish_valid_request(&binding, &mut mailbox);
        let mut register_reads = 0;
        let request = binding
            .decode_request(|| {
                register_reads += 1;
                Ok(MailboxRequest {
                    frame: carrick_guest_mem::Aarch64SyscallFrame {
                        x0: 90,
                        x1: 91,
                        x2: 92,
                        x3: 93,
                        x4: 94,
                        x5: 95,
                        x8: 172,
                    },
                    native_nr: 172,
                    resume_pc: 0x7777,
                    spsr: 0,
                    fp: 0,
                    lr: 0,
                    sp: 0,
                    esr: 0,
                })
            })
            .expect("legacy request");
        assert_eq!(request.frame.x8, 172);
        assert_eq!(register_reads, 1);
    }

    #[test]
    fn explicit_register_resume_prepares_only_an_outstanding_request() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::RequestReady.raw()
        );
        binding
            .publish_register_resume_if_outstanding()
            .expect("prepared resume");
        assert_eq!(
            mailbox.response_action,
            MailboxResponseAction::RegistersPrepared.raw()
        );
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );
        binding
            .publish_register_resume_if_outstanding()
            .expect("prepared response overwrite");
        mailbox
            .state
            .store(MailboxState::Idle.raw(), Ordering::Release);
        binding
            .publish_register_resume_if_outstanding()
            .expect("idle resume");
    }

    #[test]
    fn pending_normal_return_is_exact_and_register_resume_supersedes_it() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        binding.take_request().unwrap().expect("request");
        binding.publish_normal_return(-77).expect("normal return");
        assert_eq!(binding.pending_normal_return().unwrap(), Some(-77));

        binding
            .publish_register_resume_if_outstanding()
            .expect("signal prepared registers");
        assert_eq!(binding.pending_normal_return().unwrap(), None);
    }

    #[test]
    fn pending_normal_return_rejects_stale_generation_and_sequence() {
        let (mut binding, mut mailbox) = binding();
        publish_valid_request(&binding, &mut mailbox);
        binding.take_request().unwrap().expect("request");
        binding.publish_normal_return(91).expect("normal return");

        mailbox.generation = mailbox.generation.wrapping_add(1);
        assert!(matches!(
            binding.pending_normal_return(),
            Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::StaleGeneration { .. }
            ))
        ));
        mailbox.generation = binding.generation();
        mailbox.sequence = mailbox.sequence.wrapping_add(1);
        assert!(matches!(
            binding.pending_normal_return(),
            Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::ResponseSequenceMismatch { .. }
            ))
        ));
    }

    #[test]
    fn interruption_phase_model_dispatches_and_responds_once() {
        let (mut binding, mut mailbox) = binding();

        // Before construction and during unpublished payload mutation, the host
        // owns nothing and cannot dispatch.
        assert!(binding.take_request().expect("idle").is_none());
        mailbox.args[0] = 0xfeed;
        assert!(binding.take_request().expect("partial payload").is_none());

        // Publication transfers one request to the host. Re-consuming the same
        // sequence while host ownership is held fails closed.
        publish_valid_request(&binding, &mut mailbox);
        assert!(binding.take_request().expect("request").is_some());
        assert!(matches!(
            binding.take_request(),
            Err(MailboxConsumeError::Protocol(
                MailboxProtocolError::NonIncreasingSequence { .. }
            ))
        ));

        // Response payload alone does not transfer ownership. Publication does,
        // and a second response for the same request is rejected.
        mailbox.return_value = 77;
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::RequestReady.raw()
        );
        binding.publish_normal_return(77).expect("response");
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );
        assert!(binding.publish_normal_return(88).is_err());

        // Model the vector's final release store after EL0 return. No stale
        // request remains dispatchable.
        mailbox
            .state
            .store(MailboxState::Idle.raw(), Ordering::Release);
        assert!(binding.take_request().expect("returned idle").is_none());
    }
}
