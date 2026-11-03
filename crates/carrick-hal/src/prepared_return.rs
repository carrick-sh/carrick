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
}
#[derive(Debug)]
pub struct AppliedReturn {
    pub revision: u64,
    pub last_unmapped: Vec<FrameId>,
    pub mm_empty_at_revision: bool,
}
/// Inventory-owned implementation. Methods must not acquire an outer lock.
pub trait ReturnClaim: Send {
    fn owner(&self) -> FrameInventoryReceiptOwner;
    fn apply(self: Box<Self>) -> AppliedReturn;
    fn abort(self: Box<Self>);
    fn abandon(self: Box<Self>);
    fn retain_quarantined(self: Box<Self>);
}
pub trait ReturnQuarantine: Send + Sync {
    fn quarantine(&self, owner: FrameInventoryReceiptOwner);
}
#[must_use]
pub struct PreparedReturn {
    claim: Option<Box<dyn ReturnClaim>>,
}
impl PreparedReturn {
    pub fn from_inventory(claim: Box<dyn ReturnClaim>) -> Self {
        Self { claim: Some(claim) }
    }
    pub fn abort(mut self) {
        if let Some(claim) = self.claim.take() {
            claim.abort();
        }
    }
    pub fn apply(mut self) -> AppliedReturn {
        self.claim
            .take()
            .unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!("hal::prepared_return", "owned return claim missing")
            })
            .apply()
    }
    pub fn stage1_cleared(mut self, quarantine: Arc<dyn ReturnQuarantine>) -> Stage1Cleared {
        Stage1Cleared {
            claim: self.claim.take(),
            quarantine,
        }
    }
}
impl Drop for PreparedReturn {
    fn drop(&mut self) {
        if let Some(claim) = self.claim.take() {
            claim.abandon();
        }
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
    claim: Option<Box<dyn ReturnClaim>>,
    quarantine: Arc<dyn ReturnQuarantine>,
}
impl Stage1Cleared {
    pub fn apply(mut self) -> AppliedReturn {
        self.claim
            .take()
            .unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!("hal::prepared_return", "owned return claim missing")
            })
            .apply()
    }
    /// The caller retains the undo log and restores all leaves before returning.
    pub fn undo_and_abort(mut self, undo: impl FnOnce()) {
        undo();
        if let Some(claim) = self.claim.take() {
            claim.abort();
        }
    }
}
impl Drop for Stage1Cleared {
    fn drop(&mut self) {
        if let Some(claim) = self.claim.take() {
            self.quarantine.quarantine(claim.owner());
            claim.retain_quarantined();
        }
    }
}
