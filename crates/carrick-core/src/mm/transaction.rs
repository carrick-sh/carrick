//! Revalidation publishes the one bounded copy fence after exact observation.
use super::transfer::{SelectedChunk, TransferContinuation, TransferError, ValidatedChunk};
use carrick_sched_core::SpaceEditor;

/// # Safety
/// `editor`, revision and output must be authenticated by the exact live MM owner.
pub unsafe fn validate_selection<'a>(
    continuation: &TransferContinuation,
    selected: SelectedChunk,
    editor: SpaceEditor<'a>,
    generation: u64,
    output: Option<(u64, bool)>,
) -> Result<Option<ValidatedChunk<'a>>, TransferError> {
    if !selected.matches(continuation) {
        return Err(TransferError::Stale);
    }
    let current = output.map(|(ipa, executable)| {
        (
            ipa,
            continuation.intent == carrick_core_abi::PortalTransferIntent::UserWrite && executable,
        )
    });
    if generation != selected.generation || current != Some((selected.ipa, selected.executable)) {
        return Ok(None);
    }
    Ok(Some(ValidatedChunk {
        selected,
        _editor: editor,
    }))
}

mod error;
pub use error::MmError;
pub mod owner;
pub use owner::*;
