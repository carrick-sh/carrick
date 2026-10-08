//! Bounded physical working-table storage in the retained CPL0 root arena.
//! This licenses supervisor descriptor storage, not an MM or guest mapping.
use carrick_guest_arch::{FrameGpa, GuestLen};
use core::num::NonZeroUsize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86PrepareTableSpan {
    start: FrameGpa,
    end: FrameGpa,
}
impl X86PrepareTableSpan {
    /// Each physical lane can stop with one owner-selected Prepare window.
    /// A page-aligned target window may intersect two tables at each lower
    /// x86 level; capacity follows the canonical owner window bound.
    pub fn working_bytes(physical_lanes: NonZeroUsize) -> Option<GuestLen> {
        let maximum = crate::EL1_FRAME_GRANT_TARGET_SIZE;
        if maximum < 4096 || !maximum.is_multiple_of(4096) {
            return None;
        }
        let per_lane = [1_u64 << 21, 1_u64 << 30, 1_u64 << 39]
            .into_iter()
            .try_fold(0_u64, |count, coverage| {
                count.checked_add((maximum - 4096).div_ceil(coverage) + 1)
            })?;
        if per_lane > carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS as u64 {
            return None;
        }
        let bytes = per_lane
            .checked_mul(u64::try_from(physical_lanes.get()).ok()?)?
            .checked_mul(4096)?;
        Some(GuestLen::new(bytes))
    }
    /// `occupied_end` includes every actual serialized record and initial
    /// frame grant; the retained physical owner must separately prove zero
    /// bytes and backing custody before issuing loans from this suffix.
    pub fn derive(
        extent_bytes: GuestLen,
        occupied_end: FrameGpa,
        physical_lanes: NonZeroUsize,
    ) -> Option<Self> {
        let base = crate::X86_CPL0_INITIAL_EXTENT_GPA;
        let bytes = extent_bytes.raw();
        if bytes == 0
            || bytes > crate::X86_CPL0_INITIAL_EXTENT_MAX_SIZE
            || !bytes.is_multiple_of(4096)
            || !occupied_end.raw().is_multiple_of(4096)
            || occupied_end.raw() < base
        {
            return None;
        }
        let end = base.checked_add(bytes)?;
        let start = end.checked_sub(Self::working_bytes(physical_lanes)?.raw())?;
        if start < base || occupied_end.raw() > start {
            return None;
        }
        Some(Self {
            start: FrameGpa::new(start),
            end: FrameGpa::new(end),
        })
    }
    pub const fn start(self) -> FrameGpa {
        self.start
    }
    pub const fn end(self) -> FrameGpa {
        self.end
    }
    pub const fn len(self) -> GuestLen {
        GuestLen::new(self.end.raw() - self.start.raw())
    }
    pub const fn is_empty(self) -> bool {
        false
    }
    pub fn page_count(self) -> usize {
        (self.len().raw() / 4096) as usize
    }
    pub fn contains_word(self, address: FrameGpa) -> bool {
        address.raw().is_multiple_of(8)
            && address.raw() >= self.start.raw()
            && address
                .raw()
                .checked_add(8)
                .is_some_and(|end| end <= self.end.raw())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn working_table_aperture_preserves_disjoint_word_custody() {
        let lanes = NonZeroUsize::new(2).unwrap();
        let base = crate::X86_CPL0_INITIAL_EXTENT_GPA;
        assert_eq!(
            X86PrepareTableSpan::working_bytes(lanes),
            Some(GuestLen::new(12 * 4096))
        );
        let expected = X86PrepareTableSpan {
            start: FrameGpa::new(base + 0x14000),
            end: FrameGpa::new(base + 0x20000),
        };
        assert_eq!(
            X86PrepareTableSpan::derive(
                GuestLen::new(0x20000),
                FrameGpa::new(base + 0x10000),
                lanes
            ),
            Some(expected)
        );
        assert!(expected.contains_word(expected.start()));
        assert!(expected.contains_word(FrameGpa::new(expected.end().raw() - 8)));
        for address in [
            base + 0x8000,
            base + 0x10000,
            base + 0x13ff8,
            base + 0x14001,
            base + 0x20000,
        ] {
            assert!(!expected.contains_word(FrameGpa::new(address)));
        }
        for (extent, occupied) in [
            (0x18000, base + 0x10000),
            (0x20000, base + 0x15000),
            (0x20001, base + 0x10000),
            (0x20000, base - 4096),
        ] {
            assert!(
                X86PrepareTableSpan::derive(GuestLen::new(extent), FrameGpa::new(occupied), lanes)
                    .is_none()
            );
        }
    }
}
