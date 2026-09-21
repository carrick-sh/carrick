pub const AARCH64_SYSCALL_MAILBOX_MAGIC: u64 = 0x4341_5252_4d42_4f58;
pub const AARCH64_SYSCALL_MAILBOX_VERSION: u32 = 3;
pub const AARCH64_SYSCALL_MAILBOX_SIZE: u64 = 0x100;
pub const AARCH64_SYSCALL_MAILBOX_SLOTS: usize = 256;
pub use carrick_mem::memory::Aarch64SyscallMailbox;

const _: () = assert!(core::mem::size_of::<Aarch64SyscallMailbox>() == 256);
const _: () = assert!(core::mem::align_of::<Aarch64SyscallMailbox>() == 64);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, magic) == 0);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, version) == 8);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, size) == 12);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, generation) == 16);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, sequence) == 24);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, state) == 32);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind) == 36);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, response_action) == 40);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, flags) == 44);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, native_nr) == 48);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, args) == 56);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, portal_quantum_epoch) == 104);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc) == 112);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, spsr) == 120);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, fp) == 128);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, lr) == 136);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, sp) == 144);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, esr) == 152);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, return_value) == 160);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, resume_x16) == 168);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, resume_x17) == 176);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x16) == 216);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x17) == 224);
const _: () =
    assert!(core::mem::offset_of!(Aarch64SyscallMailbox, portal_executor_generation) == 232);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, portal_task_serial) == 240);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, portal_mm_generation) == 248);
// The guest vector lives in `carrick-mem` (below this protocol crate in the
// dependency graph), so it owns the instruction-immediate constants. Tie every
// offset it emits back to this wire struct at compile time to prevent drift.
const _: () =
    assert!(AARCH64_SYSCALL_MAILBOX_SIZE == carrick_mem::memory::LINUX_SYSCALL_MAILBOX_SLOT_SIZE);
const _: () =
    assert!(AARCH64_SYSCALL_MAILBOX_SLOTS == carrick_mem::memory::LINUX_SYSCALL_MAILBOX_SLOTS);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, sequence)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_SEQUENCE as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, state)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_STATE as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_TRAP_KIND as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, response_action)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESPONSE_ACTION as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, flags)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_FLAGS as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, native_nr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_NATIVE_NR as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, args)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_ARGS as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, portal_quantum_epoch)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_PORTAL_QUANTUM_EPOCH as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESUME_PC as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, spsr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_SPSR as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, fp)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_FP as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, lr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_LR as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, sp)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_SP as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, esr)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_ESR as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, return_value)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RETURN_VALUE as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, resume_x16)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESUME_X16 as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, resume_x17)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_RESUME_X17 as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, portal_executor_generation)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_PORTAL_EXECUTOR_GENERATION as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, portal_task_serial)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_PORTAL_TASK_SERIAL as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, portal_mm_generation)
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

const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, clock_x9)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X9 as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, clock_x10)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X10 as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, clock_x11)
        == carrick_mem::memory::AARCH64_SYSCALL_MAILBOX_OFF_CLOCK_X11 as usize
);
const _: () = assert!(
    core::mem::offset_of!(Aarch64SyscallMailbox, clock_x12)
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
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, magic), 0);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, version), 8);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, size), 12);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, generation), 16);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, sequence), 24);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, state), 32);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind), 36);
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, response_action),
            40
        );
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, flags), 44);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, native_nr), 48);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, args), 56);
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, portal_quantum_epoch),
            104
        );
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc), 112);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, spsr), 120);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, fp), 128);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, lr), 136);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, sp), 144);
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, esr), 152);
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, return_value),
            160
        );
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, resume_x16),
            168
        );
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, resume_x17),
            176
        );
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x16),
            216
        );
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, clock_tmp_x17),
            224
        );
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, portal_executor_generation),
            232
        );
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, portal_task_serial),
            240
        );
        assert_eq!(
            core::mem::offset_of!(Aarch64SyscallMailbox, portal_mm_generation),
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

        assert_eq!(MailboxState::try_from(3), Ok(MailboxState::ClockActive));
        assert_eq!(MailboxState::try_from(4), Err(UnknownMailboxValue(4)));
        assert_eq!(MailboxTrapKind::try_from(2), Err(UnknownMailboxValue(2)));
        assert_eq!(
            MailboxResponseAction::try_from(4),
            Err(UnknownMailboxValue(4))
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
}
