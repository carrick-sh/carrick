use std::sync::atomic::AtomicU32;

pub const AARCH64_SYSCALL_MAILBOX_MAGIC: u64 = 0x4341_5252_4d42_4f58;
pub const AARCH64_SYSCALL_MAILBOX_VERSION: u32 = 1;
pub const AARCH64_SYSCALL_MAILBOX_SIZE: u64 = 0x100;
pub const AARCH64_SYSCALL_MAILBOX_SLOTS: usize = 256;

#[repr(C, align(64))]
pub struct Aarch64SyscallMailbox {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub generation: u64,
    pub sequence: u64,
    pub state: AtomicU32,
    pub trap_kind: u32,
    pub response_action: u32,
    pub flags: u32,
    pub native_nr: u64,
    pub args: [u64; 6],
    pub x8: u64,
    pub resume_pc: u64,
    pub spsr: u64,
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub esr: u64,
    pub return_value: u64,
    pub resume_x16: u64,
    pub resume_x17: u64,
    pub reserved: [u8; 72],
}

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
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, x8) == 104);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc) == 112);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, spsr) == 120);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, fp) == 128);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, lr) == 136);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, sp) == 144);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, esr) == 152);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, return_value) == 160);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, resume_x16) == 168);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, resume_x17) == 176);
const _: () = assert!(core::mem::offset_of!(Aarch64SyscallMailbox, reserved) == 184);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MailboxState {
    Idle = 0,
    RequestReady = 1,
    ResponseReady = 2,
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
    NonIncreasingSequence { last: u64, actual: u64 },
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
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, x8), 104);
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
        assert_eq!(core::mem::offset_of!(Aarch64SyscallMailbox, reserved), 184);
    }

    #[test]
    fn mailbox_wire_values_are_unique_and_stable() {
        assert_eq!(MailboxState::Idle.raw(), 0);
        assert_eq!(MailboxState::RequestReady.raw(), 1);
        assert_eq!(MailboxState::ResponseReady.raw(), 2);
        assert_eq!(MailboxTrapKind::Syscall.raw(), 1);
        assert_eq!(MailboxResponseAction::NormalReturn.raw(), 1);
        assert_eq!(MailboxResponseAction::RegistersPrepared.raw(), 2);

        assert_eq!(MailboxState::try_from(3), Err(UnknownMailboxValue(3)));
        assert_eq!(MailboxTrapKind::try_from(2), Err(UnknownMailboxValue(2)));
        assert_eq!(
            MailboxResponseAction::try_from(3),
            Err(UnknownMailboxValue(3))
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
}
