//! Authenticated native-run dependency failures, distinct from supervisor faults.
use crate::ExecutionBinding;

pub const NATIVE_RUN_FAILURE_PORT: u16 = 0xd5;
/// EL1 HVC #3 discriminator; distinct from architectural faults and panics.
pub const NATIVE_RUN_FAILURE_SENTINEL: u64 = 0x4352_5255_4e46_4149;

pub use carrick_personality_linux::native_run_failure::NativeRunFailureReason;

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
mod tests {
    #[test]
    fn arm_terminal_native_failure_authenticates_once_and_counts_exactly() {
        let binding = crate::ExecutionBinding {
            task: crate::EntryTaskKey::from_raw(41),
            generation: crate::EntryGeneration::from_raw(11),
            mm: crate::EntryMmKey::from_raw(301),
            thread_generation: crate::EntryThreadGeneration::from_raw(101),
        };
        let reason = super::NativeRunFailureReason::X86GroupExitCustody;
        let record = super::NativeRunFailure::new(binding, reason);
        let mut consumer = super::NativeRunFailureConsumer::default();
        let foreign = crate::ExecutionBinding {
            thread_generation: crate::EntryThreadGeneration::from_raw(102),
            ..binding
        };
        assert_eq!(consumer.consume(&record, foreign), None);
        assert_eq!(consumer.crossings(), 0);
        assert_eq!(consumer.consume(&record, binding), Some((reason, 1)));
        assert_eq!(consumer.consume(&record, binding), None);
        assert_eq!(consumer.crossings(), 1);
        let mut exhausted = super::NativeRunFailureConsumer {
            crossings: u64::MAX,
            consumed: false,
        };
        assert_eq!(exhausted.consume(&record, binding), None);
        assert!(!exhausted.consumed);
    }

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
        record.words[5] = u64::MAX;
        assert_eq!(record.reason_for(binding), None);
    }
}
