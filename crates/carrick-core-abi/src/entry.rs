//! Exact execution identity presented at a native entry boundary.

/// Neutral binding between one executor entry and its exact task/MM owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBinding {
    pub task: u64,
    pub generation: u64,
    pub mm: u64,
    pub thread_generation: u64,
}

impl ExecutionBinding {
    pub const fn issued(self) -> bool {
        self.task != 0 && self.generation != 0
    }
}

/// Exact token which owns completion of one admitted entry.
#[derive(Debug, Eq, PartialEq)]
pub struct EntryCompletion {
    binding: ExecutionBinding,
}

impl EntryCompletion {
    pub const fn admit(binding: ExecutionBinding) -> Option<Self> {
        if binding.issued() {
            Some(Self { binding })
        } else {
            None
        }
    }

    pub const fn binding(&self) -> ExecutionBinding {
        self.binding
    }
}
