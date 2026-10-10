//! Authenticated native-run dependency failures, distinct from supervisor faults.
use crate::ExecutionBinding;

pub const NATIVE_RUN_FAILURE_PORT: u16 = 0xd5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum NativeRunFailureReason {
    X86GroupExitCustody = 1,
}
impl NativeRunFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86GroupExitCustody => "x86 group exit custody",
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
        match self.words[5] {
            1 => Some(NativeRunFailureReason::X86GroupExitCustody),
            _ => None,
        }
    }
}
const _: () = {
    assert!(core::mem::size_of::<NativeRunFailure>() == 64);
    assert!(core::mem::align_of::<NativeRunFailure>() == 64);
};

#[cfg(test)]
mod tests {
    #[test]
    fn native_run_failure_is_bound_to_the_exact_thread_incarnation() {
        let binding = crate::ExecutionBinding {
            task: crate::EntryTaskKey::from_raw(41),
            generation: crate::EntryGeneration::from_raw(11),
            mm: crate::EntryMmKey::from_raw(301),
            thread_generation: crate::EntryThreadGeneration::from_raw(101),
        };
        let mut record = super::NativeRunFailure::new(
            binding,
            super::NativeRunFailureReason::X86GroupExitCustody,
        );
        assert_eq!(
            record.reason_for(binding),
            Some(super::NativeRunFailureReason::X86GroupExitCustody)
        );
        let foreign = crate::ExecutionBinding {
            thread_generation: crate::EntryThreadGeneration::from_raw(102),
            ..binding
        };
        assert_eq!(record.reason_for(foreign), None);
        record.words[7] = 1;
        assert_eq!(record.reason_for(binding), None);
        record.words[7] = 0;
        record.words[5] = 2;
        assert_eq!(record.reason_for(binding), None);
    }
}
