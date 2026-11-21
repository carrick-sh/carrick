pub const AARCH64_SYSCALL_MAILBOX_MAGIC: u64 = 0x4341_5252_4d42_4f58;
pub const AARCH64_SYSCALL_MAILBOX_VERSION: u32 = 3;
pub const AARCH64_SYSCALL_MAILBOX_SIZE: u64 = 0x100;
pub const AARCH64_SYSCALL_MAILBOX_SLOTS: usize = 256;
pub use carrick_mem::memory::Aarch64SyscallMailbox;

const _: () = assert!(core::mem::size_of::<Aarch64SyscallMailbox>() == 256);
const _: () = assert!(core::mem::align_of::<Aarch64SyscallMailbox>() == 64);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, magic) == 0);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, version) == 8);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, size) == 12);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, generation) == 16);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, sequence) == 24);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, state) == 32);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind) == 36);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, response_action) == 40);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, flags) == 44);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, native_nr) == 48);
const _: () = ::std::assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, args) == 56);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, portal_quantum_epoch) == 104);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc) == 112);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, spsr) == 120);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, fp) == 128);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, lr) == 136);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, sp) == 144);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, esr) == 152);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, return_value) == 160);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, resume_x16) == 168);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, resume_x17) == 176);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x16) == 216);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x17) == 224);
const _: () =
    assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, portal_executor_generation) == 232);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, portal_task_serial) == 240);
const _: () = assert!(::core::mem::offset_of!(Aarch64SyscallMailbox, portal_mm_generation) == 248);
// The guest vector lives in `carrick-mem` (below this protocol crate in the
// dependency graph), so it owns the instruction-immediate constants. Tie every
// offset it emits back to this wire struct at compile time to prevent drift.
const _: () =
    assert!(AARCH64_SYSCALL_MAILBOX_SIZE == carrick_mem::memory::LINUX_SYSCALL_MAILBOX_SLOT_SIZE);
const _: () =
    assert!(AARCH64_SYSCALL_MAILBOX_SLOTS == carrick_mem::memory::LINUX_SYSCALL_MAILBOX_SLOTS);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, sequence)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_SEQUENCE as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, state)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_STATE as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_TRAP_KIND as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, response_action)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESPONSE_ACTION as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, flags)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_FLAGS as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, native_nr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_NATIVE_NR as usize
);
const _: () = ::std::assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, args)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_ARGS as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_quantum_epoch)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_PORTAL_QUANTUM_EPOCH as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESUME_PC as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, spsr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_SPSR as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, fp)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_FP as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, lr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_LR as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, sp)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_SP as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, esr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_ESR as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, return_value)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RETURN_VALUE as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, resume_x16)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESUME_X16 as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, resume_x17)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESUME_X17 as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_executor_generation)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_PORTAL_EXECUTOR_GENERATION as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_task_serial)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_PORTAL_TASK_SERIAL as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_mm_generation)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_PORTAL_MM_GENERATION as usize
);

/// Set only while the vCPU is stopped and its owned mailbox is stable.
pub const CLOCK_FORCE_HOST_BOUNDARY: u32 = carrick_mem::memory::CLOCK_FORCE_HOST_BOUNDARY;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MailboxState {
    Idle = 0,
    RequestReady = 1,
    ResponseReady = 2,
    ClockActive = 3,
}

impl MailboxState {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Idle, Self::RequestReady)
                | (Self::RequestReady, Self::ResponseReady)
                | (Self::ResponseReady, Self::Idle)
                | (Self::Idle, Self::ClockActive)
                | (Self::ClockActive, Self::Idle)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MailboxTrapKind {
    Syscall = 1,
}

impl MailboxTrapKind {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MailboxResponseAction {
    NormalReturn = 1,
    RegistersPrepared = 2,
    NormalReturnAndArmPortal = 3,
    NativeSignalCheckpoint = 4,
    NativeSignalCheckpointNoRestart = 5,
    /// Fatal-only handoff; no return value belongs to this response.
    NativeOwnerCancel = 6,
}

impl MailboxResponseAction {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownMailboxValue(pub u32);

impl TryFrom<u32> for MailboxState {
    type Error = UnknownMailboxValue;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Idle),
            1 => Ok(Self::RequestReady),
            2 => Ok(Self::ResponseReady),
            3 => Ok(Self::ClockActive),
            unknown => Err(UnknownMailboxValue(unknown)),
        }
    }
}

impl TryFrom<u32> for MailboxTrapKind {
    type Error = UnknownMailboxValue;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Syscall),
            unknown => Err(UnknownMailboxValue(unknown)),
        }
    }
}

impl TryFrom<u32> for MailboxResponseAction {
    type Error = UnknownMailboxValue;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NormalReturn),
            2 => Ok(Self::RegistersPrepared),
            3 => Ok(Self::NormalReturnAndArmPortal),
            4 => Ok(Self::NativeSignalCheckpoint),
            5 => Ok(Self::NativeSignalCheckpointNoRestart),
            6 => Ok(Self::NativeOwnerCancel),
            unknown => Err(UnknownMailboxValue(unknown)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxRequestMetadata {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub generation: u64,
    pub sequence: u64,
    pub state: u32,
    pub trap_kind: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxProtocolError {
    WrongMagic { actual: u64 },
    WrongVersion { actual: u32 },
    WrongSize { actual: u32 },
    StaleGeneration { expected: u64, actual: u64 },
    UnexpectedState { expected: MailboxState, actual: u32 },
    UnknownTrapKind(u32),
    UnknownResponseAction(u32),
    NonIncreasingSequence { last: u64, actual: u64 },
    ResponseSequenceMismatch { expected: u64, actual: u64 },
}

pub fn validate_request_metadata(
    metadata: MailboxRequestMetadata,
    expected_generation: u64,
    last_sequence: u64,
) -> Result<(), MailboxProtocolError> {
    if metadata.magic != AARCH64_SYSCALL_MAILBOX_MAGIC {
        return Err(MailboxProtocolError::WrongMagic {
            actual: metadata.magic,
        });
    }
    if metadata.version != AARCH64_SYSCALL_MAILBOX_VERSION {
        return Err(MailboxProtocolError::WrongVersion {
            actual: metadata.version,
        });
    }
    if metadata.size != AARCH64_SYSCALL_MAILBOX_SIZE as u32 {
        return Err(MailboxProtocolError::WrongSize {
            actual: metadata.size,
        });
    }
    if metadata.generation != expected_generation {
        return Err(MailboxProtocolError::StaleGeneration {
            expected: expected_generation,
            actual: metadata.generation,
        });
    }
    if MailboxState::try_from(metadata.state) != Ok(MailboxState::RequestReady) {
        return Err(MailboxProtocolError::UnexpectedState {
            expected: MailboxState::RequestReady,
            actual: metadata.state,
        });
    }
    if MailboxTrapKind::try_from(metadata.trap_kind) != Ok(MailboxTrapKind::Syscall) {
        return Err(MailboxProtocolError::UnknownTrapKind(metadata.trap_kind));
    }
    if metadata.sequence <= last_sequence {
        return Err(MailboxProtocolError::NonIncreasingSequence {
            last: last_sequence,
            actual: metadata.sequence,
        });
    }
    Ok(())
}

pub const fn next_nonzero_generation(current: u64) -> u64 {
    let next = current.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

/// Exact executor/task/MM identity published for an armed portal session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PortalSessionWire {
    pub executor_generation: u64,
    pub task_serial: u64,
    pub mm_generation: u64,
    pub quantum_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PortalState {
    Disabled = 0,
    RequestReady = 1,
    ResponseReady = 2,
    Armed = 4,
    HostBoundary = 5,
    Cancelling = 6,
}

impl PortalState {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Disabled, Self::Armed)
                | (Self::Armed, Self::RequestReady)
                | (Self::RequestReady, Self::ResponseReady | Self::HostBoundary)
                | (Self::ResponseReady | Self::HostBoundary, Self::Armed)
                | (
                    Self::Armed | Self::RequestReady | Self::ResponseReady,
                    Self::Cancelling
                )
                | (Self::Cancelling, Self::Disabled)
        )
    }
}

impl TryFrom<u32> for PortalState {
    type Error = UnknownMailboxValue;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::RequestReady),
            2 => Ok(Self::ResponseReady),
            4 => Ok(Self::Armed),
            5 => Ok(Self::HostBoundary),
            6 => Ok(Self::Cancelling),
            unknown => Err(UnknownMailboxValue(unknown)),
        }
    }
}

pub const fn portal_scalar_eligible(native_nr: u64) -> bool {
    matches!(native_nr, 62 | 28)
}

/// Decoded `Aarch64SyscallMailbox` request payload published before `HVC #2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxRequest {
    pub frame: carrick_guest_mem::Aarch64SyscallFrame,
    pub native_nr: u64,
    pub resume_pc: u64,
    pub spsr: u64,
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub esr: u64,
}

/// Snapshot of a stopped `Aarch64SyscallMailbox` slot for error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxDiagnostics {
    pub generation: u64,
    pub sequence: u64,
    pub state: u32,
    pub response_action: u32,
    pub native_nr: u64,
    pub return_value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxSlotError {
    Protocol(MailboxProtocolError),
    MissingRequest,
}

impl core::fmt::Display for MailboxSlotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(err) => write!(f, "aarch64 syscall mailbox protocol error: {err:?}"),
            Self::MissingRequest => write!(f, "aarch64 syscall mailbox was idle on HVC #2"),
        }
    }
}

/// Architectural `HVC #imm` carrier exit classification shared across AArch64
/// backends (`carrick_hal::aarch64` syndrome immediates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvcImmediateKind {
    /// `hvc #1`: stage-1 TLBI maintenance trampoline finished.
    Maintenance,
    /// `hvc #2`: EL1 syscall forward or non-SVC lower-EL synchronous fault.
    SyscallOrFault,
    /// `hvc #3`: unexpected current-EL synchronous exception trap.
    CurrentElFault,
    /// `hvc #4`: lower-EL IRQ kick boundary trap.
    Kick,
    /// `hvc #5`: in-guest scheduler idle exit.
    Idle,
    /// `hvc #6`: EL1 dynamic metadata extent grant/return hypercall.
    MetadataGrant,
    /// `hvc #7`: host-driven EL1 service return or effect yield.
    ServiceReturn,
    /// Any unallocated `HVC` immediate.
    Unknown(u16),
}

#[must_use]
pub const fn classify_hvc_immediate(immediate: u16) -> HvcImmediateKind {
    match immediate {
        1 => HvcImmediateKind::Maintenance,
        2 => HvcImmediateKind::SyscallOrFault,
        3 => HvcImmediateKind::CurrentElFault,
        4 => HvcImmediateKind::Kick,
        5 => HvcImmediateKind::Idle,
        6 => HvcImmediateKind::MetadataGrant,
        7 => HvcImmediateKind::ServiceReturn,
        other => HvcImmediateKind::Unknown(other),
    }
}

/// Portable single-slot `Aarch64SyscallMailbox` host binding.
///
/// Owns protocol generation and sequence tracking over a caller-pinned 256-byte
/// `Aarch64SyscallMailbox` mapping so non-HVF backends (the soft AArch64 VMM)
/// consume and answer `HVC #2` publications identically to HVF.
pub struct MailboxSlot {
    host: core::ptr::NonNull<Aarch64SyscallMailbox>,
    generation: u64,
    last_sequence: u64,
}

// SAFETY: `MailboxSlot` owns stopped-vCPU protocol state for a pinned
// `Aarch64SyscallMailbox` slot whose backing outlives the vCPU; moving the
// binding between host threads while the vCPU is stopped preserves exclusive
// host ownership.
unsafe impl Send for MailboxSlot {}

impl MailboxSlot {
    /// Initialize `host` as an idle `Aarch64SyscallMailbox` slot at `generation`.
    ///
    /// # Safety
    ///
    /// `host` must point to a valid, 64-byte-aligned, exclusively owned
    /// 256-byte `Aarch64SyscallMailbox` allocation that outlives all operations
    /// on this `MailboxSlot` until the next `rebind` or drop, and the vCPU
    /// sharing this slot must be stopped during `new` / `rebind`.
    pub unsafe fn new(host: core::ptr::NonNull<Aarch64SyscallMailbox>, generation: u64) -> Self {
        let generation = if generation == 0 { 1 } else { generation };
        let mut slot = Self {
            host,
            generation,
            last_sequence: 0,
        };
        // SAFETY: upheld by caller.
        unsafe { slot.rebind(host, generation) };
        slot
    }

    /// Re-initialize the slot header at `host` with `generation`.
    ///
    /// # Safety
    ///
    /// Same requirements as [`Self::new`].
    pub unsafe fn rebind(
        &mut self,
        host: core::ptr::NonNull<Aarch64SyscallMailbox>,
        generation: u64,
    ) {
        let generation = if generation == 0 {
            next_nonzero_generation(self.generation)
        } else {
            generation
        };
        self.host = host;
        self.generation = generation;
        self.last_sequence = 0;
        let ptr = self.host.as_ptr();
        // SAFETY: caller guarantees exclusive stopped access to a valid 256B slot.
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).magic),
                AARCH64_SYSCALL_MAILBOX_MAGIC,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).version),
                AARCH64_SYSCALL_MAILBOX_VERSION,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).size),
                AARCH64_SYSCALL_MAILBOX_SIZE as u32,
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).generation), generation);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).sequence), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).flags), 0);
            (*ptr).state.store(
                MailboxState::Idle.raw(),
                core::sync::atomic::Ordering::Release,
            );
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.last_sequence
    }

    fn state(&self) -> &core::sync::atomic::AtomicU32 {
        // SAFETY: `self.host` points to a live `Aarch64SyscallMailbox`.
        unsafe { &(*self.host.as_ptr()).state }
    }

    #[must_use]
    pub fn diagnostics(&self) -> MailboxDiagnostics {
        let ptr = self.host.as_ptr();
        let state = self.state().load(core::sync::atomic::Ordering::Acquire);
        // SAFETY: `self.host` points to a live slot sampled while the vCPU is stopped.
        unsafe {
            MailboxDiagnostics {
                generation: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).generation)),
                sequence: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).sequence)),
                state,
                response_action: core::ptr::read_volatile(core::ptr::addr_of!(
                    (*ptr).response_action
                )),
                native_nr: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).native_nr)),
                return_value: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).return_value)),
            }
        }
    }

    /// Validate and observe a guest-published `RequestReady` payload on `HVC #2`.
    /// Returns `Ok(None)` when the slot is `Idle` (a non-SVC synchronous fault).
    pub fn take_request(&mut self) -> Result<Option<MailboxRequest>, MailboxSlotError> {
        let state = self.state().load(core::sync::atomic::Ordering::Acquire);
        if state == MailboxState::Idle.raw() {
            return Ok(None);
        }
        let ptr = self.host.as_ptr();
        // SAFETY: acquire load of `state` synchronizes with the guest's release
        // publication while the vCPU is stopped at synchronous `HVC #2`.
        let (metadata, request) = unsafe {
            let metadata = MailboxRequestMetadata {
                magic: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).magic)),
                version: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).version)),
                size: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).size)),
                generation: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).generation)),
                sequence: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).sequence)),
                state,
                trap_kind: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).trap_kind)),
            };
            let args = core::ptr::read_volatile(&raw const (*ptr).args);
            let native_nr = core::ptr::read_volatile(core::ptr::addr_of!((*ptr).native_nr));
            let request = MailboxRequest {
                frame: carrick_guest_mem::Aarch64SyscallFrame {
                    x0: args[0],
                    x1: args[1],
                    x2: args[2],
                    x3: args[3],
                    x4: args[4],
                    x5: args[5],
                    x8: native_nr,
                },
                native_nr,
                resume_pc: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).resume_pc)),
                spsr: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).spsr)),
                fp: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).fp)),
                lr: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).lr)),
                sp: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).sp)),
                esr: core::ptr::read_volatile(core::ptr::addr_of!((*ptr).esr)),
            };
            (metadata, request)
        };
        validate_request_metadata(metadata, self.generation, self.last_sequence)
            .map_err(MailboxSlotError::Protocol)?;
        self.last_sequence = metadata.sequence;
        // Clear any latched host-clock boundary once host dispatch observes the request.
        unsafe {
            let flags = core::ptr::read_volatile(core::ptr::addr_of!((*ptr).flags));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).flags),
                flags & !CLOCK_FORCE_HOST_BOUNDARY,
            );
        }
        Ok(Some(request))
    }

    fn require_request_ready(&self) -> Result<(), MailboxSlotError> {
        let state = self.state().load(core::sync::atomic::Ordering::Acquire);
        if state != MailboxState::RequestReady.raw() {
            return Err(MailboxSlotError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::RequestReady,
                    actual: state,
                },
            ));
        }
        let ptr = self.host.as_ptr();
        // SAFETY: stopped slot owned by this binding.
        let (magic, version, size, generation, sequence) = unsafe {
            (
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).magic)),
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).version)),
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).size)),
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).generation)),
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).sequence)),
            )
        };
        if magic != AARCH64_SYSCALL_MAILBOX_MAGIC {
            return Err(MailboxSlotError::Protocol(
                MailboxProtocolError::WrongMagic { actual: magic },
            ));
        }
        if version != AARCH64_SYSCALL_MAILBOX_VERSION {
            return Err(MailboxSlotError::Protocol(
                MailboxProtocolError::WrongVersion { actual: version },
            ));
        }
        if size != AARCH64_SYSCALL_MAILBOX_SIZE as u32 {
            return Err(MailboxSlotError::Protocol(
                MailboxProtocolError::WrongSize { actual: size },
            ));
        }
        if generation != self.generation {
            return Err(MailboxSlotError::Protocol(
                MailboxProtocolError::StaleGeneration {
                    expected: self.generation,
                    actual: generation,
                },
            ));
        }
        if sequence != self.last_sequence {
            return Err(MailboxSlotError::Protocol(
                MailboxProtocolError::ResponseSequenceMismatch {
                    expected: self.last_sequence,
                    actual: sequence,
                },
            ));
        }
        Ok(())
    }

    pub fn publish_return_with_action(
        &mut self,
        value: i64,
        action: MailboxResponseAction,
    ) -> Result<(), MailboxSlotError> {
        self.require_request_ready()?;
        let ptr = self.host.as_ptr();
        // SAFETY: `RequestReady` ownership verified above; `ResponseReady` is
        // published with Release ordering after both payload words complete.
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).return_value), value as u64);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).response_action),
                action.raw(),
            );
        }
        self.state().store(
            MailboxState::ResponseReady.raw(),
            core::sync::atomic::Ordering::Release,
        );
        Ok(())
    }

    pub fn publish_normal_return(&mut self, value: i64) -> Result<(), MailboxSlotError> {
        self.publish_return_with_action(value, MailboxResponseAction::NormalReturn)
    }

    pub fn publish_native_signal_return(
        &mut self,
        value: i64,
        restart_eligible: bool,
    ) -> Result<(), MailboxSlotError> {
        self.publish_return_with_action(
            value,
            if restart_eligible {
                MailboxResponseAction::NativeSignalCheckpoint
            } else {
                MailboxResponseAction::NativeSignalCheckpointNoRestart
            },
        )
    }

    pub fn pending_normal_return(&self) -> Result<Option<i64>, MailboxSlotError> {
        let state = self.state().load(core::sync::atomic::Ordering::Acquire);
        match MailboxState::try_from(state) {
            Ok(MailboxState::ResponseReady) => {}
            Ok(MailboxState::Idle | MailboxState::RequestReady | MailboxState::ClockActive) => {
                return Ok(None);
            }
            Err(unknown) => {
                return Err(MailboxSlotError::Protocol(
                    MailboxProtocolError::UnexpectedState {
                        expected: MailboxState::ResponseReady,
                        actual: unknown.0,
                    },
                ));
            }
        }
        let ptr = self.host.as_ptr();
        // SAFETY: `ResponseReady` acquired above.
        let (action, value) = unsafe {
            (
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).response_action)),
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).return_value)),
            )
        };
        if action == MailboxResponseAction::NormalReturn.raw()
            || action == MailboxResponseAction::NormalReturnAndArmPortal.raw()
        {
            Ok(Some(value as i64))
        } else {
            Ok(None)
        }
    }

    pub fn prepare_register_resume(&mut self) -> Result<(), MailboxSlotError> {
        let state = self.state().load(core::sync::atomic::Ordering::Acquire);
        if state == MailboxState::Idle.raw() {
            return Ok(());
        }
        if state != MailboxState::RequestReady.raw() && state != MailboxState::ResponseReady.raw() {
            return Err(MailboxSlotError::Protocol(
                MailboxProtocolError::UnexpectedState {
                    expected: MailboxState::RequestReady,
                    actual: state,
                },
            ));
        }
        let ptr = self.host.as_ptr();
        // SAFETY: stopped slot owned by this binding.
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*ptr).response_action),
                MailboxResponseAction::RegistersPrepared.raw(),
            );
        }
        self.state().store(
            MailboxState::ResponseReady.raw(),
            core::sync::atomic::Ordering::Release,
        );
        Ok(())
    }
}

const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, clock_x9)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X9 as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, clock_x10)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X10 as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, clock_x11)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X11 as usize
);
const _: () = assert!(
    ::core::mem::offset_of!(Aarch64SyscallMailbox, clock_x12)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X12 as usize
);
const _: () = assert!(
    MailboxState::ClockActive.raw() == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_CLOCK_ACTIVE
);
const _: () =
    assert!(PortalState::Armed.raw() == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_PORTAL_ARMED);
const _: () = assert!(
    PortalState::HostBoundary.raw()
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_PORTAL_HOST_BOUNDARY
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_layout_is_fixed() {
        assert_eq!(core::mem::size_of::<Aarch64SyscallMailbox>(), 256);
        assert_eq!(core::mem::align_of::<Aarch64SyscallMailbox>(), 64);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, magic), 0);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, version), 8);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, size), 12);
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, generation),
            16
        );
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, sequence), 24);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, state), 32);
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind),
            36
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, response_action),
            40
        );
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, flags), 44);
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, native_nr),
            48
        );
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, args), 56);
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_quantum_epoch),
            104
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc),
            112
        );
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, spsr), 120);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, fp), 128);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, lr), 136);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, sp), 144);
        assert_eq!(::core::mem::offset_of!(Aarch64SyscallMailbox, esr), 152);
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, return_value),
            160
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, resume_x16),
            168
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, resume_x17),
            176
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x16),
            216
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x17),
            224
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_executor_generation),
            232
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_task_serial),
            240
        );
        assert_eq!(
            ::core::mem::offset_of!(Aarch64SyscallMailbox, portal_mm_generation),
            248
        );
    }

    #[test]
    fn mailbox_wire_values_are_unique_and_stable() {
        assert_eq!(MailboxState::Idle.raw(), 0);
        assert_eq!(MailboxState::RequestReady.raw(), 1);
        assert_eq!(MailboxState::ResponseReady.raw(), 2);
        assert_eq!(MailboxTrapKind::Syscall.raw(), 1);
        assert_eq!(MailboxResponseAction::NormalReturn.raw(), 1);
        assert_eq!(MailboxResponseAction::RegistersPrepared.raw(), 2);
        assert_eq!(MailboxResponseAction::NormalReturnAndArmPortal.raw(), 3);
        assert_eq!(MailboxResponseAction::NativeSignalCheckpoint.raw(), 4);
        assert_eq!(
            MailboxResponseAction::NativeSignalCheckpointNoRestart.raw(),
            5
        );

        assert_eq!(MailboxState::try_from(3), Ok(MailboxState::ClockActive));
        assert_eq!(MailboxState::try_from(4), Err(UnknownMailboxValue(4)));
        assert_eq!(MailboxTrapKind::try_from(2), Err(UnknownMailboxValue(2)));
        assert_eq!(
            MailboxResponseAction::try_from(4),
            Ok(MailboxResponseAction::NativeSignalCheckpoint)
        );
        assert_eq!(
            MailboxResponseAction::try_from(5),
            Ok(MailboxResponseAction::NativeSignalCheckpointNoRestart)
        );
    }

    #[test]
    fn mailbox_ownership_transition_is_linear() {
        assert!(MailboxState::Idle.can_transition_to(MailboxState::RequestReady));
        assert!(MailboxState::RequestReady.can_transition_to(MailboxState::ResponseReady));
        assert!(MailboxState::ResponseReady.can_transition_to(MailboxState::Idle));
        assert!(!MailboxState::Idle.can_transition_to(MailboxState::ResponseReady));
        assert!(!MailboxState::RequestReady.can_transition_to(MailboxState::Idle));
    }

    fn valid_metadata() -> MailboxRequestMetadata {
        MailboxRequestMetadata {
            magic: AARCH64_SYSCALL_MAILBOX_MAGIC,
            version: AARCH64_SYSCALL_MAILBOX_VERSION,
            size: AARCH64_SYSCALL_MAILBOX_SIZE as u32,
            generation: 9,
            sequence: 11,
            state: MailboxState::RequestReady.raw(),
            trap_kind: MailboxTrapKind::Syscall.raw(),
        }
    }

    #[test]
    fn request_metadata_rejects_stale_and_duplicate_publications() {
        let mut metadata = valid_metadata();
        assert_eq!(validate_request_metadata(metadata, 9, 10), Ok(()));

        metadata.generation = 8;
        assert_eq!(
            validate_request_metadata(metadata, 9, 10),
            Err(MailboxProtocolError::StaleGeneration {
                expected: 9,
                actual: 8
            })
        );
        metadata = valid_metadata();
        metadata.sequence = 10;
        assert_eq!(
            validate_request_metadata(metadata, 9, 10),
            Err(MailboxProtocolError::NonIncreasingSequence {
                last: 10,
                actual: 10
            })
        );
    }

    #[test]
    fn unpublished_payload_and_wrong_trap_kind_fail_closed() {
        let mut metadata = valid_metadata();
        metadata.state = MailboxState::Idle.raw();
        assert!(matches!(
            validate_request_metadata(metadata, 9, 10),
            Err(MailboxProtocolError::UnexpectedState { .. })
        ));

        metadata = valid_metadata();
        metadata.trap_kind = 99;
        assert_eq!(
            validate_request_metadata(metadata, 9, 10),
            Err(MailboxProtocolError::UnknownTrapKind(99))
        );
    }

    #[test]
    fn response_cannot_publish_before_request_ownership() {
        let mut metadata = valid_metadata();
        metadata.state = MailboxState::ResponseReady.raw();
        assert!(matches!(
            validate_request_metadata(metadata, 9, 10),
            Err(MailboxProtocolError::UnexpectedState { .. })
        ));
    }

    #[test]
    fn generation_rollover_never_publishes_zero() {
        assert_eq!(next_nonzero_generation(0), 1);
        assert_eq!(next_nonzero_generation(41), 42);
        assert_eq!(next_nonzero_generation(u64::MAX), 1);
    }

    #[test]
    fn portal_wire_layout_and_transitions_are_closed() {
        assert_eq!(core::mem::size_of::<PortalSessionWire>(), 32);
        assert_eq!(PortalState::try_from(0), Ok(PortalState::Disabled));
        assert_eq!(PortalState::try_from(4), Ok(PortalState::Armed));
        assert_eq!(PortalState::try_from(5), Ok(PortalState::HostBoundary));
        assert_eq!(PortalState::try_from(6), Ok(PortalState::Cancelling));
        assert_eq!(PortalState::try_from(3), Err(UnknownMailboxValue(3)));
        assert_eq!(PortalState::try_from(7), Err(UnknownMailboxValue(7)));

        assert!(PortalState::Disabled.can_transition_to(PortalState::Armed));
        assert!(PortalState::Armed.can_transition_to(PortalState::RequestReady));
        assert!(PortalState::RequestReady.can_transition_to(PortalState::ResponseReady));
        assert!(PortalState::ResponseReady.can_transition_to(PortalState::Armed));
        assert!(PortalState::RequestReady.can_transition_to(PortalState::HostBoundary));
        assert!(PortalState::HostBoundary.can_transition_to(PortalState::Armed));
        for state in [
            PortalState::Armed,
            PortalState::RequestReady,
            PortalState::ResponseReady,
        ] {
            assert!(state.can_transition_to(PortalState::Cancelling));
        }
        assert!(PortalState::Cancelling.can_transition_to(PortalState::Disabled));
        assert!(!PortalState::Disabled.can_transition_to(PortalState::ResponseReady));
        assert!(!PortalState::Armed.can_transition_to(PortalState::Disabled));
    }

    #[test]
    fn portal_scalar_allowlist_is_exact() {
        assert_eq!(carrick_abi::syscall::nr::LSEEK.raw(), 62);
        assert_eq!(carrick_abi::syscall::nr::INOTIFY_RM_WATCH.raw(), 28);
        assert!(portal_scalar_eligible(62));
        assert!(portal_scalar_eligible(28));
        for native_nr in [0, 1, 27, 29, 63, 64, 124, 293] {
            assert!(
                !portal_scalar_eligible(native_nr),
                "unexpected syscall {native_nr}"
            );
        }
    }

    #[test]
    fn hvc_immediates_classify_canonically() {
        assert_eq!(classify_hvc_immediate(1), HvcImmediateKind::Maintenance);
        assert_eq!(classify_hvc_immediate(2), HvcImmediateKind::SyscallOrFault);
        assert_eq!(classify_hvc_immediate(3), HvcImmediateKind::CurrentElFault);
        assert_eq!(classify_hvc_immediate(4), HvcImmediateKind::Kick);
        assert_eq!(classify_hvc_immediate(5), HvcImmediateKind::Idle);
        assert_eq!(classify_hvc_immediate(6), HvcImmediateKind::MetadataGrant);
        assert_eq!(classify_hvc_immediate(7), HvcImmediateKind::ServiceReturn);
        assert_eq!(classify_hvc_immediate(9), HvcImmediateKind::Unknown(9));
    }

    #[test]
    fn mailbox_slot_round_trips_request_and_response() {
        // SAFETY: `Aarch64SyscallMailbox` is `#[repr(C)]` of integer and `AtomicU32`
        // fields for which all-zero bytes are valid.
        let mut backing: Box<Aarch64SyscallMailbox> = unsafe { Box::new_zeroed().assume_init() };
        let ptr = core::ptr::NonNull::from(backing.as_mut());
        // SAFETY: `backing` is a pinned 64-byte-aligned 256-byte mailbox owned by this test.
        let mut slot = unsafe { MailboxSlot::new(ptr, 7) };
        assert_eq!(slot.generation(), 7);
        assert_eq!(slot.take_request(), Ok(None));

        // Simulate guest EL1 vector publishing RequestReady for `write(1, 0x4000, 12)`.
        backing.sequence = 1;
        backing.trap_kind = MailboxTrapKind::Syscall.raw();
        backing.native_nr = 64;
        backing.args = [1, 0x4000, 12, 0, 0, 0];
        backing.resume_pc = 0x21_0134;
        backing.sp = 0xffff_ff00;
        backing.flags = CLOCK_FORCE_HOST_BOUNDARY;
        backing.state.store(
            MailboxState::RequestReady.raw(),
            core::sync::atomic::Ordering::Release,
        );

        let request = slot.take_request().unwrap().unwrap();
        assert_eq!(request.native_nr, 64);
        assert_eq!(request.frame.x0, 1);
        assert_eq!(request.frame.x1, 0x4000);
        assert_eq!(request.frame.x2, 12);
        assert_eq!(request.resume_pc, 0x21_0134);
        assert_eq!(request.sp, 0xffff_ff00);
        assert_eq!(backing.flags & CLOCK_FORCE_HOST_BOUNDARY, 0);

        slot.publish_normal_return(12).unwrap();
        assert_eq!(slot.pending_normal_return(), Ok(Some(12)));
        assert_eq!(
            backing.state.load(core::sync::atomic::Ordering::Acquire),
            MailboxState::ResponseReady.raw()
        );
        assert_eq!(
            backing.response_action,
            MailboxResponseAction::NormalReturn.raw()
        );
    }
}
