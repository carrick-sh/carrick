use super::*;
use alloc::vec;

const X86: ImageGeometry = ImageGeometry::X86_64;
const STACK: ImageStack = ImageStack {
    top: UserVa::new(0x7fff_0000_0000),
    size: GuestLen::new(0x2_0000),
};

fn row(start: u64, len: u64, perms: &str) -> ImageRow {
    ImageRow {
        start: UserVa::new(start),
        len: GuestLen::new(len),
        initialized_offset: GuestLen::new(0),
        initialized_len: GuestLen::new(len.min(0x800)),
        readable: perms.contains('r'),
        writable: perms.contains('w'),
        executable: perms.contains('x'),
    }
}

/// A static executable (text, data) and its interpreter (text), the shape the
/// host imports for an exec successor.
fn good() -> vec::Vec<ImageRow> {
    vec![
        row(0x40_0000, 0x2000, "rx"),
        row(0x60_0000, 0x3000, "rw"),
        row(0x7f00_0000_0000, 0x1000, "rx"),
    ]
}

fn check(rows: &[ImageRow]) -> Result<ValidatedImage, ImageRowError> {
    validate_image_rows(rows, 2, UserVa::new(0x7f00_0000_0010), STACK, X86)
}

#[test]
fn a_well_formed_successor_image_is_accepted_with_the_executable_break() {
    assert_eq!(
        check(&good()),
        Ok(ValidatedImage {
            initial_break: UserVa::new(0x60_3000),
        }),
        "brk follows the executable prefix, never the interpreter"
    );
    // The executable's rows need not precede each other in address order.
    let mut rows = good();
    rows.swap(0, 1);
    assert_eq!(
        validate_image_rows(&rows, 2, UserVa::new(0x40_0010), STACK, X86),
        Ok(ValidatedImage {
            initial_break: UserVa::new(0x60_3000),
        })
    );
}

#[test]
fn malformed_successor_rows_are_refused_with_their_exact_reason() {
    assert_eq!(check(&[]), Err(ImageRowError::NoRows));
    assert_eq!(
        validate_image_rows(&good(), 0, UserVa::new(0x40_0000), STACK, X86),
        Err(ImageRowError::ExecutablePrefix)
    );
    assert_eq!(
        validate_image_rows(&good(), 4, UserVa::new(0x40_0000), STACK, X86),
        Err(ImageRowError::ExecutablePrefix)
    );

    let mut rows = good();
    rows[1].start = UserVa::new(0x60_0800);
    assert_eq!(check(&rows), Err(ImageRowError::Unaligned { row: 1 }));
    let mut rows = good();
    rows[1].len = GuestLen::new(0x1800);
    assert_eq!(check(&rows), Err(ImageRowError::Unaligned { row: 1 }));

    let mut rows = good();
    rows[1].len = GuestLen::new(0);
    rows[1].initialized_len = GuestLen::new(0);
    assert_eq!(check(&rows), Err(ImageRowError::EmptyRow { row: 1 }));

    let mut rows = good();
    rows[0].start = UserVa::new(0);
    assert_eq!(check(&rows), Err(ImageRowError::OutsideUser { row: 0 }));
    let mut rows = good();
    rows[2].start = UserVa::new((1 << 47) - 0x1000);
    rows[2].len = GuestLen::new(0x2000);
    assert_eq!(check(&rows), Err(ImageRowError::OutsideUser { row: 2 }));
    let mut rows = good();
    rows[2].start = UserVa::new(u64::MAX - 0xfff);
    assert_eq!(check(&rows), Err(ImageRowError::OutsideUser { row: 2 }));

    let mut rows = good();
    rows[1].initialized_offset = GuestLen::new(0x2900);
    assert_eq!(check(&rows), Err(ImageRowError::Initialized { row: 1 }));

    let mut rows = good();
    rows[1].readable = false;
    assert_eq!(check(&rows), Err(ImageRowError::Permissions { row: 1 }));

    let stack = ImageStack {
        top: UserVa::new(0x7fff_0000_0800),
        size: STACK.size,
    };
    assert_eq!(
        validate_image_rows(&good(), 2, UserVa::new(0x40_0000), stack, X86),
        Err(ImageRowError::Stack)
    );
    let stack = ImageStack {
        top: STACK.top,
        size: GuestLen::new(0),
    };
    assert_eq!(
        validate_image_rows(&good(), 2, UserVa::new(0x40_0000), stack, X86),
        Err(ImageRowError::Stack)
    );

    // Data, not text, holds the entry; and an entry past every row.
    assert_eq!(
        validate_image_rows(&good(), 2, UserVa::new(0x60_0000), STACK, X86),
        Err(ImageRowError::Entry)
    );
    assert_eq!(
        validate_image_rows(&good(), 2, UserVa::new(0x40_2000), STACK, X86),
        Err(ImageRowError::Entry)
    );
}

#[test]
fn overlapping_successor_rows_name_both_rows() {
    // The interpreter collides with the executable's data.
    let mut rows = good();
    rows[2].start = UserVa::new(0x60_2000);
    assert_eq!(
        check(&rows),
        Err(ImageRowError::Overlap {
            first: 1,
            second: 2
        })
    );
    // Order in the slice does not change which rows are named.
    rows.swap(1, 2);
    assert_eq!(
        validate_image_rows(&rows, 2, UserVa::new(0x40_0000), STACK, X86),
        Err(ImageRowError::Overlap {
            first: 2,
            second: 1
        })
    );
    // Touching rows do not overlap.
    let mut rows = good();
    rows[1].start = UserVa::new(0x40_2000);
    assert!(check(&rows).is_ok());

    let mut rows = good();
    rows[2].start = UserVa::new(0x7fff_0000_0000 - 0x1000);
    rows[2].len = GuestLen::new(0x2000);
    assert_eq!(
        validate_image_rows(&rows, 2, UserVa::new(0x40_0000), STACK, X86),
        Err(ImageRowError::StackOverlap { row: 2 })
    );
}

#[test]
fn frame_runs_split_a_grant_into_contiguous_runs_in_grant_order() {
    let frames = [
        0x10_0000, 0x10_1000, 0x10_2000, 0x40_0000, 0x40_1000, 0x20_0000,
    ]
    .map(FrameGpa::new);
    assert_eq!(
        frame_runs(&frames, 4096),
        Ok(vec![
            FrameRun {
                start: FrameGpa::new(0x10_0000),
                pages: 3,
            },
            FrameRun {
                start: FrameGpa::new(0x40_0000),
                pages: 2,
            },
            FrameRun {
                start: FrameGpa::new(0x20_0000),
                pages: 1,
            },
        ])
    );
    assert_eq!(
        frame_runs(&[FrameGpa::new(0x10_0000)], 4096),
        Ok(vec![FrameRun {
            start: FrameGpa::new(0x10_0000),
            pages: 1,
        }])
    );
}

#[test]
fn frame_runs_refuse_null_unaligned_and_repeated_frames() {
    assert_eq!(frame_runs(&[], 4096), Err(FrameRunError::NoFrames));
    assert_eq!(
        frame_runs(&[FrameGpa::new(0x1000), FrameGpa::new(0)], 4096),
        Err(FrameRunError::Null { index: 1 })
    );
    assert_eq!(
        frame_runs(&[FrameGpa::new(0x1000), FrameGpa::new(0x2800)], 4096),
        Err(FrameRunError::Unaligned { index: 1 })
    );
    // A repeat inside a later run, not adjacent to its first grant.
    let frames = [0x1000, 0x2000, 0x9000, 0x1000].map(FrameGpa::new);
    assert_eq!(
        frame_runs(&frames, 4096),
        Err(FrameRunError::Duplicate { index: 3 })
    );
}
