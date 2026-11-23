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
    /// A committed birth's record could not be queued (#1100).
    BornEnqueueRefused = 12,
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
            Self::BornEnqueueRefused => "native birth enqueue refused",
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
            12 => Some(Self::BornEnqueueRefused),
            _ => None,
        }
    }
}

impl NativeRunFailureReason {
    /// This reason, raised at the caller's source site.
    #[track_caller]
    pub fn at_caller(self) -> NativeRunFailureCause {
        NativeRunFailureCause {
            reason: self,
            site: crate::SourceSite::caller(),
        }
    }
}

/// A terminal native run failure: its reason and the kernel site that raised
/// it, so the host names the site without a per-site diagnostic build (#2853).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRunFailureCause {
    pub reason: NativeRunFailureReason,
    pub site: crate::SourceSite,
}

impl core::fmt::Display for NativeRunFailureCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at {}", self.reason.as_str(), self.site)
    }
}

/// Retained supervisor-stack record; the carrier authenticates the exact lane.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct NativeRunFailure {
    words: [u64; 16],
}
impl NativeRunFailure {
    const MAGIC: u64 = 0x4352_5255_4e46_4149;
    /// First word of the raising site's wire image.
    const SITE: usize = 6;
    /// First reserved word; every reserved word is zero.
    const RESERVED: usize = Self::SITE + crate::SOURCE_SITE_WORDS;
    pub fn new(binding: ExecutionBinding, cause: NativeRunFailureCause) -> Self {
        let mut words = [0; 16];
        words[..Self::SITE].copy_from_slice(&[
            Self::MAGIC,
            binding.task.raw(),
            binding.generation.raw(),
            binding.mm.raw(),
            binding.thread_generation.raw(),
            cause.reason as u64,
        ]);
        words[Self::SITE..Self::RESERVED].copy_from_slice(&cause.site.words());
        Self { words }
    }
    pub fn cause_for(&self, expected: ExecutionBinding) -> Option<NativeRunFailureCause> {
        if !expected.issued()
            || self.words[..5]
                != [
                    Self::MAGIC,
                    expected.task.raw(),
                    expected.generation.raw(),
                    expected.mm.raw(),
                    expected.thread_generation.raw(),
                ]
            || self.words[Self::RESERVED..].iter().any(|&word| word != 0)
        {
            return None;
        }
        let reason = NativeRunFailureReason::from_raw(self.words[5])?;
        let mut site = [0; crate::SOURCE_SITE_WORDS];
        site.copy_from_slice(&self.words[Self::SITE..Self::RESERVED]);
        Some(NativeRunFailureCause {
            reason,
            site: crate::SourceSite::from_words(site),
        })
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
    ) -> Option<(NativeRunFailureCause, u64)> {
        if self.consumed {
            return None;
        }
        let cause = record.cause_for(expected)?;
        let crossings = self.crossings.checked_add(1)?;
        self.crossings = crossings;
        self.consumed = true;
        Some((cause, crossings))
    }
}

const _: () = {
    assert!(core::mem::size_of::<NativeRunFailure>() == 128);
    assert!(core::mem::align_of::<NativeRunFailure>() == 64);
};

#[cfg(test)]
#[path = "native_run_failure_tests.rs"]
mod tests;
