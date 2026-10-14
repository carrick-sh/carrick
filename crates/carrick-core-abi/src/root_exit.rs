//! Personality-neutral terminal notification authenticated to an execution lane.
use crate::ExecutionBinding;
use carrick_sched_core::process::{TerminationKind, TerminationStatus};

pub const NATIVE_ROOT_EXIT_PORT: u16 = 0xd3;

/// One supervisor-stack record: binding, full-width code, terminal kind.
/// The host personality adapter encodes its own wait ABI after authentication.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct NativeRootExit {
    pub words: [u64; 8],
}

impl NativeRootExit {
    pub const MAGIC: u64 = 0x4352_524f_4f54_4558;

    pub fn new(binding: ExecutionBinding, status: TerminationStatus) -> Option<Self> {
        if !binding.issued() || binding.mm.raw() == 0 || binding.thread_generation.raw() == 0 {
            return None;
        }
        let kind = match status.kind() {
            TerminationKind::Exited => 0,
            TerminationKind::Signaled { core_dump: false } => 1,
            TerminationKind::Signaled { core_dump: true } => 2,
        };
        Some(Self {
            words: [
                Self::MAGIC,
                binding.task.raw(),
                binding.generation.raw(),
                binding.mm.raw(),
                binding.thread_generation.raw(),
                u64::from(status.code()),
                kind,
                0,
            ],
        })
    }

    pub fn status_for(&self, expected: ExecutionBinding) -> Option<TerminationStatus> {
        if !expected.issued()
            || expected.mm.raw() == 0
            || expected.thread_generation.raw() == 0
            || self.words[..5]
                != [
                    Self::MAGIC,
                    expected.task.raw(),
                    expected.generation.raw(),
                    expected.mm.raw(),
                    expected.thread_generation.raw(),
                ]
            || self.words[7] != 0
        {
            return None;
        }
        let code = u32::try_from(self.words[5]).ok()?;
        match self.words[6] {
            0 => Some(TerminationStatus::exited(code)),
            1 => Some(TerminationStatus::signaled(code, false)),
            2 => Some(TerminationStatus::signaled(code, true)),
            _ => None,
        }
    }

    pub fn raw_words(&self) -> [u64; 8] {
        self.words
    }
    pub fn from_raw_words(words: [u64; 8]) -> Self {
        Self { words }
    }
}

const _: () = {
    assert!(core::mem::size_of::<NativeRootExit>() == 64);
    assert!(core::mem::align_of::<NativeRootExit>() == 64);
    assert!(core::mem::offset_of!(NativeRootExit, words) == 0);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration};
    fn binding() -> ExecutionBinding {
        ExecutionBinding {
            task: EntryTaskKey::from_raw(41),
            generation: EntryGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(301),
            thread_generation: EntryThreadGeneration::from_raw(101),
        }
    }
    #[test]
    fn full_width_codes_and_kinds_round_trip() {
        for status in [
            TerminationStatus::exited(0xdead_beef),
            TerminationStatus::SUCCESS,
            TerminationStatus::exited(u32::MAX),
            TerminationStatus::signaled(0xdead_beef, false),
            TerminationStatus::signaled(u32::MAX, true),
        ] {
            let record = NativeRootExit::new(binding(), status).unwrap();
            assert_eq!(record.words[5], u64::from(status.code()));
            let copy = NativeRootExit::from_raw_words(record.raw_words());
            assert_eq!(copy.status_for(binding()), Some(status));
        }
    }
    #[test]
    fn rejects_foreign_bindings_and_malformed_wire_words() {
        let b = binding();
        let record = NativeRootExit::new(b, TerminationStatus::SUCCESS).unwrap();
        for index in 0..5 {
            let mut bad = record;
            bad.words[index] += 1;
            assert_eq!(bad.status_for(b), None);
        }
        for (index, value) in [(5, u64::from(u32::MAX) + 1), (6, 3), (7, 1)] {
            let mut bad = record;
            bad.words[index] = value;
            assert_eq!(bad.status_for(b), None);
        }
        for index in 1..5 {
            let mut words = record.words;
            words[index] = 0;
            let bad = ExecutionBinding {
                task: EntryTaskKey::from_raw(words[1]),
                generation: EntryGeneration::from_raw(words[2]),
                mm: EntryMmKey::from_raw(words[3]),
                thread_generation: EntryThreadGeneration::from_raw(words[4]),
            };
            assert!(NativeRootExit::new(bad, TerminationStatus::SUCCESS).is_none());
            assert_eq!(NativeRootExit::from_raw_words(words).status_for(bad), None);
        }
    }
}
