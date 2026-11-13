//! The CPL0 build of a native exec successor (#2235): boot's editor over
//! the reserved stock tables and inventory data grants, reading the
//! carrier's staged build extent and writing the successor's unpublished
//! frames one page at a time through the predecessor's exact-MM copy
//! window. No other supervisor alias names either frame; every leaf is
//! restored and drained before the window call returns.
use crate::entry::InitialWords;
use carrick_core_abi::service::ExecBuildSource;
use carrick_el1::isa::x86::initial_mm::{InitialMmError, InitialMmImage};
use carrick_el1::isa::x86_exec_build::{ExecBuildPlan, ExecBuildWindow};
use carrick_guest_arch::{FrameGpa, RootGpa};
use carrick_mmu_core::x86::copy_window::with_copy_window_frames;
use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
use core::num::NonZeroU64;

const PAGE: usize = 4096;

/// The predecessor's live copy window, through its authenticated live
/// context (its drains are this CPU's exact invalidations).
struct CopyWindow<'w> {
    words: &'w InitialWords,
    root: RootGpa,
}

impl CopyWindow<'_> {
    fn map<R>(
        &self,
        source: Option<FrameGpa>,
        destination: Option<FrameGpa>,
        effect: impl FnOnce(u64, u64) -> R,
    ) -> Option<R> {
        match with_copy_window_frames(self.words, self.root, source, destination, effect) {
            Ok(result) => Some(result),
            Err(DescriptorOutcome::Refused(_)) => None,
            // A leaf the window could not restore names a frame no owner
            // tracks: stop the carrier, as boot does for its editor.
            Err(_) => carrick_el1::isa::x86::fatal_entry_binding(),
        }
    }
}

impl ExecBuildWindow for CopyWindow<'_> {
    fn read(&mut self, page: FrameGpa, offset: usize, out: &mut [u8]) -> bool {
        if offset.checked_add(out.len()).is_none_or(|end| end > PAGE) {
            return false;
        }
        self.map(Some(page), None, |source, _| {
            // SAFETY: the read-only leaf maps exactly `page` until restored
            // after this closure; the span lies inside it.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (source as usize + offset) as *const u8,
                    out.as_mut_ptr(),
                    out.len(),
                );
            }
        })
        .is_some()
    }

    fn write(&mut self, page: FrameGpa, offset: usize, bytes: &[u8]) -> bool {
        if offset.checked_add(bytes.len()).is_none_or(|end| end > PAGE) {
            return false;
        }
        self.map(None, Some(page), |_, destination| {
            // SAFETY: the writable leaf maps exactly `page`, a frame no
            // published descriptor names yet; the span lies inside it.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (destination as usize + offset) as *mut u8,
                    bytes.len(),
                );
            }
        })
        .is_some()
    }

    fn copy(
        &mut self,
        source: FrameGpa,
        source_offset: usize,
        destination: FrameGpa,
        destination_offset: usize,
        len: usize,
    ) -> bool {
        if source == destination
            || source_offset.checked_add(len).is_none_or(|end| end > PAGE)
            || destination_offset
                .checked_add(len)
                .is_none_or(|end| end > PAGE)
        {
            return false;
        }
        self.map(Some(source), Some(destination), |from, to| {
            // SAFETY: both leaves map exactly their frames until restored;
            // the frames are distinct and both spans lie inside them.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (from as usize + source_offset) as *const u8,
                    (to as usize + destination_offset) as *mut u8,
                    len,
                );
            }
        })
        .is_some()
    }
}

/// Build the sealed successor `mm` at `generation` from the staged extent
/// `source`, on this CPU, while the predecessor `predecessor_mm` is its live
/// address space. Returns the unpublished image; its publications and
/// results are already written back to the extent for the adoption crossing.
///
/// # Safety
/// As for [`crate::initial_boot::build_x86_successor`]: the caller owns the
/// closed, unadmitted successor and the reserved grants the extent names
/// until the successor is adopted or its preparation is cancelled.
pub unsafe fn build_exec_successor(
    predecessor_mm: carrick_el1_abi::ReservationMm,
    source: ExecBuildSource,
    mm: NonZeroU64,
    generation: NonZeroU64,
) -> Result<InitialMmImage, InitialMmError> {
    let predecessor = carrick_el1::isa::x86::hardware_live_root()
        .map_err(|_| InitialMmError::DescriptorRefused)?;
    let words =
        crate::table_span::live_words(predecessor_mm).ok_or(InitialMmError::DescriptorRefused)?;
    let mut window = CopyWindow {
        words: &words,
        root: predecessor,
    };
    let plan = ExecBuildPlan::read(&mut window, source, mm, generation)?;
    plan.build(&mut window, |frames, spec| {
        // SAFETY: forwarded from this function's contract; `predecessor` is
        // the authenticated live root `live_words` admitted.
        unsafe {
            crate::initial_boot::build_x86_successor(frames, predecessor, mm, generation, spec)
        }
    })
}
