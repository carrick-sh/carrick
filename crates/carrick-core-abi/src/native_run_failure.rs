//! Authenticated native-run dependency failures, distinct from supervisor faults.
use crate::ExecutionBinding;

pub const NATIVE_RUN_FAILURE_PORT: u16 = 0xd5;
/// EL1 HVC #3 discriminator; distinct from architectural faults and panics.
pub const NATIVE_RUN_FAILURE_SENTINEL: u64 = 0x4352_5255_4e46_4149;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum NativeRunFailureReason {
    X86GroupExitCustody = 1,
    NativeInvalid = 2,
    NativeStale = 3,
    NativeExhausted = 4,
    NativeFault = 5,
    NativeUnsupported = 6,
    NativeBusy = 7,
    NativeQuarantined = 8,
    NativeNoChild = 9,
    BirthSettlement = 10,
    ClaimRollback = 11,
}
impl NativeRunFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86GroupExitCustody => "x86 group exit custody",
            Self::NativeInvalid => "native process invalid",
            Self::NativeStale => "native process stale",
            Self::NativeExhausted => "native process exhausted",
            Self::NativeFault => "native process fault",
            Self::NativeUnsupported => "native process unsupported",
            Self::NativeBusy => "native process busy",
            Self::NativeQuarantined => "native process quarantined",
            Self::NativeNoChild => "native process no child",
            Self::BirthSettlement => "native birth settlement",
            Self::ClaimRollback => "native claim rollback",
        }
    }
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::X86GroupExitCustody),
            2 => Some(Self::NativeInvalid),
            3 => Some(Self::NativeStale),
            4 => Some(Self::NativeExhausted),
            5 => Some(Self::NativeFault),
            6 => Some(Self::NativeUnsupported),
            7 => Some(Self::NativeBusy),
            8 => Some(Self::NativeQuarantined),
            9 => Some(Self::NativeNoChild),
            10 => Some(Self::BirthSettlement),
            11 => Some(Self::ClaimRollback),
            _ => None,
        }
    }
}

/// Retained supervisor-stack record; the carrier authenticates the exact lane.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct NativeRunFailure {
    words: [u64; 8],
}
impl NativeRunFailure {
    const MAGIC: u64 = 0x4352_5255_4e46_4149;
    pub fn new(binding: ExecutionBinding, reason: NativeRunFailureReason) -> Self {
        Self {
            words: [
                Self::MAGIC,
                binding.task.raw(),
                binding.generation.raw(),
                binding.mm.raw(),
                binding.thread_generation.raw(),
                reason as u64,
                0,
                0,
            ],
        }
    }
    pub fn reason_for(&self, expected: ExecutionBinding) -> Option<NativeRunFailureReason> {
        if !expected.issued()
            || self.words[..5]
                != [
                    Self::MAGIC,
                    expected.task.raw(),
                    expected.generation.raw(),
                    expected.mm.raw(),
                    expected.thread_generation.raw(),
                ]
            || self.words[6..] != [0, 0]
        {
            return None;
        }
        NativeRunFailureReason::from_raw(self.words[5])
    }
}
/// Carrier-owned terminal crossing ledger. A successful admission is one-shot;
/// foreign records and counter exhaustion never consume an execution lane.
#[derive(Debug, Default)]
pub struct NativeRunFailureConsumer {
    crossings: u64,
    consumed: bool,
}
impl NativeRunFailureConsumer {
    pub fn crossings(&self) -> u64 {
        self.crossings
    }
    pub fn consume(
        &mut self,
        record: &NativeRunFailure,
        expected: ExecutionBinding,
    ) -> Option<(NativeRunFailureReason, u64)> {
        if self.consumed {
            return None;
        }
        let reason = record.reason_for(expected)?;
        let crossings = self.crossings.checked_add(1)?;
        self.crossings = crossings;
        self.consumed = true;
        Some((reason, crossings))
    }
}

const _: () = {
    assert!(core::mem::size_of::<NativeRunFailure>() == 64);
    assert!(core::mem::align_of::<NativeRunFailure>() == 64);
};

#[cfg(test)]
#[path = "native_run_failure_tests.rs"]
mod tests;
