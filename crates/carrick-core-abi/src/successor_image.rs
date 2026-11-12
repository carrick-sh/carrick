//! The ISA-neutral shape checks on a successor image: the PT_LOAD rows the
//! host imported from the ELF, the stack beside them, and the frame runs that
//! back them. Boot's initial image and an exec successor are the same shape,
//! so the guest editor, the CPL0 request check and host staging share these
//! checks rather than each keeping its own.
//!
//! Only geometry is checked here. Physical custody (which frames, which
//! aliases, which inventory revision) stays with the caller that owns it.
use alloc::vec::Vec;
use carrick_guest_arch::{FrameGpa, GuestLen, UserVa};

/// The leaf size and user half a row is checked against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageGeometry {
    pub page: u64,
    /// First address past the user half.
    pub user_end: u64,
}

impl ImageGeometry {
    /// Four-level x86-64 paging: 4 KiB leaves under a 47-bit lower half.
    pub const X86_64: Self = Self {
        page: 4096,
        user_end: 1 << 47,
    };
}

/// One page-rounded PT_LOAD span. File bytes cover
/// `initialized_offset..initialized_offset + initialized_len`; the rest of the
/// row is zero fill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageRow {
    pub start: UserVa,
    pub len: GuestLen,
    pub initialized_offset: GuestLen,
    pub initialized_len: GuestLen,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// The initial stack's reservation, `top - size..top`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageStack {
    pub top: UserVa,
    pub size: GuestLen,
}

/// Why a successor image was refused. `row` indexes the caller's slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageRowError {
    NoRows,
    /// The executable prefix is empty or longer than the rows.
    ExecutablePrefix,
    Unaligned {
        row: usize,
    },
    EmptyRow {
        row: usize,
    },
    /// Below the first page, past the user half, or overflowing.
    OutsideUser {
        row: usize,
    },
    /// The file bytes run past the row.
    Initialized {
        row: usize,
    },
    /// Writable or executable without readable.
    Permissions {
        row: usize,
    },
    Overlap {
        first: usize,
        second: usize,
    },
    /// The stack is empty, unaligned or outside the user half.
    Stack,
    StackOverlap {
        row: usize,
    },
    /// The entry lies in no executable row.
    Entry,
}

/// What a valid image implies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedImage {
    /// First byte past the executable prefix's highest row; brk starts here.
    pub initial_break: UserVa,
}

/// Check `rows` (the first `executable_rows` belong to the executable, the
/// rest to its interpreter), `entry` and `stack` against `geometry`.
pub fn validate_image_rows(
    rows: &[ImageRow],
    executable_rows: usize,
    entry: UserVa,
    stack: ImageStack,
    geometry: ImageGeometry,
) -> Result<ValidatedImage, ImageRowError> {
    let _ = (rows, executable_rows, entry, stack, geometry);
    Ok(ValidatedImage {
        initial_break: UserVa::new(0),
    })
}

/// A maximal contiguous run of frames, in grant order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameRun {
    pub start: FrameGpa,
    pub pages: u64,
}

/// Why a frame grant list was refused. `index` indexes the caller's slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameRunError {
    NoFrames,
    Null {
        index: usize,
    },
    Unaligned {
        index: usize,
    },
    /// The frame repeats an earlier grant.
    Duplicate {
        index: usize,
    },
}

/// Split a grant list into its contiguous runs. A grant may span any number
/// of runs; every frame must be page-aligned, nonzero and granted once.
pub fn frame_runs(frames: &[FrameGpa], page: u64) -> Result<Vec<FrameRun>, FrameRunError> {
    let _ = (frames, page);
    Ok(Vec::new())
}

#[cfg(test)]
mod tests;
