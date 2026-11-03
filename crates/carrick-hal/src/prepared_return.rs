//! Claimed inventory returns and the stage-1 commit boundary.
use crate::{FrameId, FrameInventoryReceiptOwner, FrameLength, MappingGeneration, MappingId};
use carrick_guest_mem::Gpa;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactReturnMappingRow {
    pub mapping: MappingId,
    pub frame: FrameId,
    pub generation: MappingGeneration,
    pub gpa: Gpa,
    pub length: FrameLength,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PrepareReturnError {
    #[error("return chunk exceeds 512 pages or is empty")]
    Capacity,
    #[error("return row is stale, claimed, or belongs to another owner")]
    RowMismatch,
    #[error("inventory revision exhausted")]
    RevisionExhausted,
    #[error("return preparation unsupported")]
    Unsupported,
    #[error("frame has no authenticated physical allocator identity")]
    MissingPhysicalIdentity,
}
/// The generation published by a claimed unmap, reserved before stage-1 clear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnmappedReturnRow {
    pub mapping: MappingId,
    pub frame: FrameId,
    pub generation: MappingGeneration,
}
#[derive(Debug)]
pub struct AppliedReturn {
    pub revision: u64,
    pub receipt: crate::FrameInventoryApplyReceipt,
    pub unmapped: Vec<UnmappedReturnRow>,
    pub last_unmapped: Vec<crate::FrameRetirementPermit>,
    pub mm_empty_at_revision: bool,
}
/// Inventory-owned implementation. Methods must not acquire an outer lock.
/// Dropping a prepared claim restores its rows; after `stage1_cleared`, dropping
/// it must quarantine the exact owner instead. Consuming methods disarm drop.
pub trait ReturnClaim: Send {
    fn apply(self: Box<Self>) -> AppliedReturn;
    fn abort(self: Box<Self>);
    fn stage1_cleared(&mut self, quarantine: Arc<dyn ReturnQuarantine>);
}
pub trait ReturnQuarantine: Send + Sync {
    fn quarantine(&self, owner: FrameInventoryReceiptOwner);
}
#[must_use]
pub struct PreparedReturn {
    claim: Box<dyn ReturnClaim>,
}
impl PreparedReturn {
    pub fn from_inventory(claim: Box<dyn ReturnClaim>) -> Self {
        Self { claim }
    }
    pub fn abort(self) {
        self.claim.abort();
    }
    pub fn apply(self) -> AppliedReturn {
        self.claim.apply()
    }
    pub fn stage1_cleared(mut self, quarantine: Arc<dyn ReturnQuarantine>) -> Stage1Cleared {
        self.claim.stage1_cleared(quarantine);
        Stage1Cleared { claim: self.claim }
    }
}
/// After clearing stage-1, ordinary abort is unavailable.
/// ```compile_fail
/// fn cannot_abort(cleared: carrick_hal::prepared_return::Stage1Cleared) {
///     cleared.abort();
/// }
/// ```
/// Apply returns a value, never a fallible result.
/// ```compile_fail
/// fn cannot_retry(prepared: carrick_hal::prepared_return::PreparedReturn) {
///     prepared.apply().unwrap();
/// }
/// ```
#[must_use]
pub struct Stage1Cleared {
    claim: Box<dyn ReturnClaim>,
}
impl Stage1Cleared {
    pub fn apply(self) -> AppliedReturn {
        self.claim.apply()
    }
    /// The caller retains the undo log and restores all leaves before returning.
    pub fn undo_and_abort(self, undo: impl FnOnce()) {
        undo();
        self.claim.abort();
    }
}
