//! Address-space (MM) records of the memory-ownership core (#3061, PR 1a).
//!
//! An MM is admitted the first time the shell presents an exclusion of it,
//! and leaves when the shell retires it. Its record holds the editor state
//! ([`super::MmEditor`]); its copy-on-write grants live in the core's grant
//! index and name it as their owner.

use core::num::NonZeroU64;

use super::editor::MmEditor;

/// One guest address space of one carrier, by the key the guest's space
/// table publishes for it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct MmKey(NonZeroU64);

impl MmKey {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

/// The core's record of one admitted MM.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct MmRecord {
    pub(super) editor: MmEditor,
}

impl MmRecord {
    pub(super) const fn admitted() -> Self {
        Self {
            editor: MmEditor::Free,
        }
    }
}
