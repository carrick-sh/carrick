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
    if rows.is_empty() {
        return Err(ImageRowError::NoRows);
    }
    if executable_rows == 0 || executable_rows > rows.len() {
        return Err(ImageRowError::ExecutablePrefix);
    }
    let page = geometry.page;
    let mut spans = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let start = row.start.raw();
        let len = row.len.raw();
        if !start.is_multiple_of(page) || !len.is_multiple_of(page) {
            return Err(ImageRowError::Unaligned { row: index });
        }
        if len == 0 {
            return Err(ImageRowError::EmptyRow { row: index });
        }
        let end = start
            .checked_add(len)
            .filter(|end| start >= page && *end <= geometry.user_end)
            .ok_or(ImageRowError::OutsideUser { row: index })?;
        if row
            .initialized_offset
            .raw()
            .checked_add(row.initialized_len.raw())
            .is_none_or(|initialized| initialized > len)
        {
            return Err(ImageRowError::Initialized { row: index });
        }
        if !row.readable && (row.writable || row.executable) {
            return Err(ImageRowError::Permissions { row: index });
        }
        spans.push((start, end, index));
    }
    let top = stack.top.raw();
    let floor = top
        .checked_sub(stack.size.raw())
        .filter(|floor| {
            stack.size.raw() != 0
                && top.is_multiple_of(page)
                && stack.size.raw().is_multiple_of(page)
                && *floor >= page
                && top <= geometry.user_end
        })
        .ok_or(ImageRowError::Stack)?;
    spans.sort_unstable_by_key(|&(start, _, _)| start);
    if let Some(pair) = spans.windows(2).find(|pair| pair[0].1 > pair[1].0) {
        return Err(ImageRowError::Overlap {
            first: pair[0].2,
            second: pair[1].2,
        });
    }
    if let Some(&(_, _, row)) = spans
        .iter()
        .find(|&&(start, end, _)| start < top && floor < end)
    {
        return Err(ImageRowError::StackOverlap { row });
    }
    if !rows.iter().any(|row| {
        row.executable
            && entry.raw() >= row.start.raw()
            && entry.raw() - row.start.raw() < row.len.raw()
    }) {
        return Err(ImageRowError::Entry);
    }
    let initial_break = rows[..executable_rows]
        .iter()
        .map(|row| row.start.raw() + row.len.raw())
        .max()
        .ok_or(ImageRowError::ExecutablePrefix)?;
    Ok(ValidatedImage {
        initial_break: UserVa::new(initial_break),
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
    if frames.is_empty() {
        return Err(FrameRunError::NoFrames);
    }
    let mut runs: Vec<FrameRun> = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        if frame.raw() == 0 {
            return Err(FrameRunError::Null { index });
        }
        if !frame.raw().is_multiple_of(page) {
            return Err(FrameRunError::Unaligned { index });
        }
        match runs.last_mut() {
            Some(run)
                if run
                    .pages
                    .checked_mul(page)
                    .and_then(|bytes| run.start.raw().checked_add(bytes))
                    == Some(frame.raw()) =>
            {
                run.pages += 1;
            }
            _ => runs.push(FrameRun {
                start: *frame,
                pages: 1,
            }),
        }
    }
    let mut order: Vec<usize> = (0..frames.len()).collect();
    order.sort_unstable_by_key(|&index| (frames[index].raw(), index));
    if let Some(pair) = order
        .windows(2)
        .find(|pair| frames[pair[0]] == frames[pair[1]])
    {
        return Err(FrameRunError::Duplicate { index: pair[1] });
    }
    Ok(runs)
}

#[cfg(test)]
mod tests;
