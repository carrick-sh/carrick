//! Whole-word output admission for operations that publish resources.
//! Supply runs before admission; one editor then fences all eight bytes,
//! including an unaligned word spanning two different physical pages.
use carrick_guest_arch::{Gpa, GuestLen};
use carrick_sched_core::SpaceEditor;

/// A physical piece of an eight-byte user output, in byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WordWritePiece {
    pub address: Gpa,
    pub len: GuestLen,
    pub executable: bool,
}

/// Exact-MM mapping stability for the entire output. This is not physical
/// memory custody: the output venue must retain/map both pieces before any
/// resource publication, and perform its infallible writes before dropping
/// this fence. Never retain it over growth, supply, I/O or suspension.
#[must_use = "retain the fence through final output publication"]
pub struct WordWriteFence<'a, Context: Copy + Send + Sync + zerocopy::FromZeros> {
    pub(super) pieces: [WordWritePiece; 2],
    pub(super) count: usize,
    pub(super) _editor: SpaceEditor<'a, Context>,
}
impl<Context: Copy + Send + Sync + zerocopy::FromZeros> WordWriteFence<'_, Context> {
    pub fn pieces(&self) -> &[WordWritePiece] {
        &self.pieces[..self.count]
    }
}

/// A whole-word destination whose physical mappings are retained by borrowed
/// slices. Its only effect is an infallible eight-byte write. Construct before
/// descriptor publication; consume afterward, outside the descriptor lock.
pub struct WordWriteOutput<'a, 'mm, Context: Copy + Send + Sync + zerocopy::FromZeros> {
    fence: WordWriteFence<'mm, Context>,
    first: &'a mut [u8],
    second: &'a mut [u8],
}
impl<'mm, Context: Copy + Send + Sync + zerocopy::FromZeros> WordWriteFence<'mm, Context> {
    /// Bind physical output storage, before any resource publication.
    ///
    /// # Safety
    /// The slices must map the exact physical pieces in `pieces()`, in order,
    /// with physical custody retained for their borrow lifetime. The venue
    /// must perform any executable-memory cache maintenance before user return.
    /// Slice access must not fault or require further owner work.
    pub unsafe fn bind<'a>(
        self,
        first: &'a mut [u8],
        second: &'a mut [u8],
    ) -> Result<WordWriteOutput<'a, 'mm, Context>, super::MmError> {
        if first.len() as u64 != self.pieces[0].len.raw()
            || second.len() as u64
                != if self.count == 2 {
                    self.pieces[1].len.raw()
                } else {
                    0
                }
        {
            return Err(super::MmError::Invalid);
        }
        Ok(WordWriteOutput {
            fence: self,
            first,
            second,
        })
    }
}
impl<Context: Copy + Send + Sync + zerocopy::FromZeros> WordWriteOutput<'_, '_, Context> {
    pub fn write(self, bytes: [u8; 8]) {
        let Self {
            fence,
            first,
            second,
        } = self;
        let split = first.len();
        first.copy_from_slice(&bytes[..split]);
        second.copy_from_slice(&bytes[split..]);
        drop(fence);
    }
}
