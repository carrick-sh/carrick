//! Classification of an EL0 write permission fault for guest EL1 fork COW.
//!
//! A fork arms an MM's EL1-private anonymous leaves read-only and marks them
//! `SW_EL1_COW`, keeping the page's Linux write intent in
//! `SW_EL1_MAY_WRITE`. The first write to such a page must give the writer a
//! private copy of the (possibly still shared) 16 KiB host compound it maps.
//! EL1 can do that itself with a host-provisioned replacement compound; this
//! module decides *which* leaves one copy moves, reading the live graph only.
//!
//! The run is the maximal set of consecutive 4 KiB pages around the fault
//! whose leaves are valid, EL1-private, COW-armed, and map consecutive pages
//! of the *same* old compound at the same offset the fault page does. Those
//! leaves repoint as one [`super::DescriptorOp::CowRepoint`] with
//! [`super::CowRepointAccess::RecordedPrivate`]: every moved page recovers
//! exactly its recorded write intent. Neighbours that are prepared, retired,
//! untagged, or map another compound keep their current output; the host's
//! settlement sees them as retained siblings of the old compound.
//!
//! Anything else is not EL1's to resolve and is forwarded: an untagged
//! backend leaf (its permissions live in host metadata), a block terminal
//! (resolving it needs a table split), a kernel-only leaf, and an armed page
//! whose Linux write intent is clear (a genuine protection fault the host
//! delivers as `SIGSEGV`).

use super::{
    AP_MASK, AP_RW, DescriptorRefusal, LeafAccess, LiveDescriptorWords, PA_MASK_4KIB, PT_PAGE,
    SW_EL1_MAY_WRITE, SW_EL1_PRIVATE, SubstrateGpa, TYPE_BITS, TYPE_TABLE_OR_PAGE, VALID, el1_cow,
    terminal_descriptor_permits_el0,
};

/// Bytes of the host COW compound a run stays inside.
pub const GUEST_COW_COMPOUND: u64 = 16 * 1024;

/// The pages one guest COW copy moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestCowRun {
    /// First page of the run.
    pub va: u64,
    /// Bytes, a multiple of 4 KiB, at most one compound.
    pub len: u64,
    /// Output of the run's first page in the old compound.
    pub old_ipa: SubstrateGpa,
}

impl GuestCowRun {
    /// The run's byte offset inside its 16 KiB compound (the same in the old
    /// and the replacement compound).
    #[must_use]
    pub fn compound_offset(&self) -> u64 {
        self.old_ipa.raw() & (GUEST_COW_COMPOUND - 1)
    }
}

/// Why a write fault is not a guest COW run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestCowClass {
    /// The live leaf already permits the write (a sibling resolved it, or a
    /// stale TLB entry faulted): retry after invalidating.
    AlreadyWritable,
    /// Not an EL1-private, COW-armed, Linux-writable 4 KiB leaf: forward.
    NotArmed(GuestCowNotArmed),
    /// The walk left the reachable primary arena.
    Unreachable(DescriptorRefusal),
}

/// Why a leaf is not one EL1 resolves as fork COW, in test order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestCowNotArmed {
    /// No valid L3 page: nothing mapped, an invalid leaf, or a block terminal
    /// above L3.
    Unmapped,
    /// A valid page that is not COW-armed (an untagged backend leaf, or a
    /// private page `mprotect`ed read-only).
    NotCowArmed,
    /// COW-armed but not EL1-private state.
    NotEl1Private,
    /// COW-armed and private, but Linux never granted write (a real
    /// protection fault).
    NoWriteIntent,
}

/// The L3 leaf mapping `va`, or `None` when a level above is not a table
/// (a block terminal, or nothing mapped).
fn l3_leaf<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: SubstrateGpa,
    va: u64,
) -> Result<Option<u64>, DescriptorRefusal> {
    let mut table = root.raw();
    for shift in [39, 30, 21] {
        let descriptor = words.load(table + ((va >> shift) & 511) * 8)?;
        if descriptor & VALID == 0 || descriptor & TYPE_BITS != TYPE_TABLE_OR_PAGE {
            return Ok(None);
        }
        table = descriptor & PA_MASK_4KIB;
    }
    words.load(table + ((va >> 12) & 511) * 8).map(Some)
}

/// A leaf this run may move: valid 4 KiB page, EL1-private, COW-armed.
fn armed_page(leaf: u64) -> bool {
    leaf & TYPE_BITS == TYPE_TABLE_OR_PAGE && el1_cow(leaf)
}

/// Whether the terminal `descriptor` at `level` is a leaf EL1 resolves as
/// fork COW: a valid 4 KiB page, EL1-private, COW-armed and Linux-writable.
#[must_use]
pub fn is_guest_cow_write_leaf(level: usize, descriptor: u64) -> bool {
    level == 3
        && armed_page(descriptor)
        && descriptor & SW_EL1_PRIVATE != 0
        && descriptor & SW_EL1_MAY_WRITE != 0
        && descriptor & AP_MASK != AP_RW
}

/// Classify an EL0 write permission fault at `far` against the live graph at
/// `root`. The caller holds the MM's exact editor.
pub fn classify_guest_cow_write<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: SubstrateGpa,
    far: u64,
) -> Result<GuestCowRun, GuestCowClass> {
    let page = far & !(PT_PAGE - 1);
    let leaf = l3_leaf(words, root, page)
        .map_err(GuestCowClass::Unreachable)?
        .ok_or(GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped))?;
    if terminal_descriptor_permits_el0(leaf, LeafAccess::Write) {
        return Err(GuestCowClass::AlreadyWritable);
    }
    if leaf & VALID == 0 {
        return Err(GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped));
    }
    if leaf & SW_EL1_PRIVATE == 0 {
        return Err(GuestCowClass::NotArmed(GuestCowNotArmed::NotEl1Private));
    }
    if !armed_page(leaf) {
        return Err(GuestCowClass::NotArmed(GuestCowNotArmed::NotCowArmed));
    }
    if leaf & SW_EL1_MAY_WRITE == 0 {
        return Err(GuestCowClass::NotArmed(GuestCowNotArmed::NoWriteIntent));
    }
    if !is_guest_cow_write_leaf(3, leaf) {
        return Err(GuestCowClass::NotArmed(GuestCowNotArmed::NotCowArmed));
    }
    let output = leaf & PA_MASK_4KIB;
    let compound = output & !(GUEST_COW_COMPOUND - 1);
    let lane = (output - compound) / PT_PAGE;
    let lanes = GUEST_COW_COMPOUND / PT_PAGE;
    // The host arms and settles COW per 16 KiB VA granule; a run never
    // leaves the fault page's granule, whatever the physical layout.
    let granule = page & !(GUEST_COW_COMPOUND - 1);
    let moves = |index: u64| -> Result<bool, GuestCowClass> {
        // Lane `index` of the compound, at the VA the fault page's offset
        // implies. Wrapping never happens: lanes stay inside one compound.
        let Some(va) = (page + index * PT_PAGE).checked_sub(lane * PT_PAGE) else {
            return Ok(false);
        };
        if va & !(GUEST_COW_COMPOUND - 1) != granule {
            return Ok(false);
        }
        Ok(l3_leaf(words, root, va)
            .map_err(GuestCowClass::Unreachable)?
            .is_some_and(|neighbour| {
                armed_page(neighbour) && neighbour & PA_MASK_4KIB == compound + index * PT_PAGE
            }))
    };
    let mut first = lane;
    while first > 0 && moves(first - 1)? {
        first -= 1;
    }
    let mut last = lane;
    while last + 1 < lanes && moves(last + 1)? {
        last += 1;
    }
    Ok(GuestCowRun {
        va: page - (lane - first) * PT_PAGE,
        len: (last - first + 1) * PT_PAGE,
        old_ipa: SubstrateGpa(compound + first * PT_PAGE),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::Cell;

    const ROOT: u64 = 0x1000;
    const VA: u64 = 0x4000_0000;
    const OLD: u64 = 0x9_0000_0000;
    const L3: u64 = 0x4000;

    struct Words(Vec<Cell<u64>>);

    impl Words {
        fn new() -> Self {
            let words = Self((0..0x5000 / 8).map(|_| Cell::new(0)).collect());
            let idx = |va: u64, shift: u64| (va >> shift) & 511;
            words.set(ROOT + idx(VA, 39) * 8, 0x2003);
            words.set(0x2000 + idx(VA, 30) * 8, 0x3003);
            words.set(0x3000 + idx(VA, 21) * 8, L3 | 3);
            words
        }
        fn set(&self, pa: u64, value: u64) {
            self.0[pa as usize / 8].set(value);
        }
        fn leaf_at(&self, va: u64, value: u64) {
            self.set(L3 + ((va >> 12) & 511) * 8, value);
        }
    }

    impl LiveDescriptorWords for Words {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            self.0
                .get(pa as usize / 8)
                .map(Cell::get)
                .ok_or(DescriptorRefusal::TableOutsidePrimary)
        }
        fn compare_exchange(&self, _: u64, _: u64, _: u64) -> Result<bool, DescriptorRefusal> {
            panic!("classification never stores")
        }
        fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
            panic!("classification never stores")
        }
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _: u64, _: u64) {}
    }

    const AF: u64 = 1 << 10;
    const AP_RO_EL0: u64 = 0b11 << 6;
    const NG: u64 = 1 << 11;
    const COW: u64 = 1 << 55;
    const PRIVATE: u64 = 1 << 56;
    const MAY_WRITE: u64 = 1 << 57;

    fn armed(ipa: u64, may_write: bool) -> u64 {
        ipa | 3 | AF | AP_RO_EL0 | NG | COW | PRIVATE | if may_write { MAY_WRITE } else { 0 }
    }

    #[test]
    fn a_fully_armed_compound_moves_as_one_run() {
        let words = Words::new();
        for lane in 0..4 {
            words.leaf_at(VA + lane * PT_PAGE, armed(OLD + lane * PT_PAGE, lane != 3));
        }
        let run = classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA + 0x2abc).unwrap();
        assert_eq!(
            run,
            GuestCowRun {
                va: VA,
                len: 4 * PT_PAGE,
                old_ipa: SubstrateGpa(OLD),
            }
        );
        assert_eq!(run.compound_offset(), 0);
    }

    #[test]
    fn the_run_follows_the_old_compound_inside_the_va_granule() {
        let words = Words::new();
        // VA page 0x..1000 maps lane 0 of the compound; the VA granule's
        // page 0 maps another compound and is not part of this copy.
        words.leaf_at(VA, armed(0x7_0000_3000, true));
        words.leaf_at(VA + PT_PAGE, armed(OLD, true));
        words.leaf_at(VA + 2 * PT_PAGE, armed(OLD + PT_PAGE, true));
        // Lane 2 is prepared (invalid): the run stops before it.
        words.leaf_at(
            VA + 3 * PT_PAGE,
            (OLD + 2 * PT_PAGE) | 2 | PRIVATE | MAY_WRITE,
        );
        let run = classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA + PT_PAGE).unwrap();
        assert_eq!(
            run,
            GuestCowRun {
                va: VA + PT_PAGE,
                len: 2 * PT_PAGE,
                old_ipa: SubstrateGpa(OLD),
            }
        );
    }

    #[test]
    fn a_mid_compound_fault_extends_both_ways_within_the_compound() {
        let words = Words::new();
        words.leaf_at(VA + PT_PAGE, armed(OLD + PT_PAGE, true));
        words.leaf_at(VA + 2 * PT_PAGE, armed(OLD + 2 * PT_PAGE, true));
        // Lane 0 maps the right compound at the wrong page: not moved.
        words.leaf_at(VA, armed(OLD + 3 * PT_PAGE, true));
        let run = classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA + 2 * PT_PAGE).unwrap();
        assert_eq!(
            run,
            GuestCowRun {
                va: VA + PT_PAGE,
                len: 2 * PT_PAGE,
                old_ipa: SubstrateGpa(OLD + PT_PAGE),
            }
        );
        assert_eq!(run.compound_offset(), PT_PAGE);
    }

    #[test]
    fn a_run_never_leaves_the_fault_pages_va_granule() {
        let words = Words::new();
        // The compound's lanes 0..3 sit at VA pages 2..5: two VA granules.
        for lane in 0..4 {
            words.leaf_at(VA + (lane + 2) * PT_PAGE, armed(OLD + lane * PT_PAGE, true));
        }
        let run = classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA + 2 * PT_PAGE).unwrap();
        assert_eq!(
            run,
            GuestCowRun {
                va: VA + 2 * PT_PAGE,
                len: 2 * PT_PAGE,
                old_ipa: SubstrateGpa(OLD),
            }
        );
        let run = classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA + 4 * PT_PAGE).unwrap();
        assert_eq!(
            run,
            GuestCowRun {
                va: VA + 4 * PT_PAGE,
                len: 2 * PT_PAGE,
                old_ipa: SubstrateGpa(OLD + 2 * PT_PAGE),
            }
        );
    }

    #[test]
    fn non_guest_leaves_and_denied_writes_are_forwarded() {
        let words = Words::new();
        // Untagged backend leaf, read-only: host metadata owns it.
        words.leaf_at(VA, OLD | 3 | AF | AP_RO_EL0 | NG);
        assert_eq!(
            classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA),
            Err(GuestCowClass::NotArmed(GuestCowNotArmed::NotEl1Private))
        );
        // Armed page without Linux write intent: a real protection fault.
        words.leaf_at(VA, armed(OLD, false));
        assert_eq!(
            classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA),
            Err(GuestCowClass::NotArmed(GuestCowNotArmed::NoWriteIntent))
        );
        // mprotect(PROT_READ) of a private page (not COW-armed).
        words.leaf_at(VA, OLD | 3 | AF | AP_RO_EL0 | NG | PRIVATE | MAY_WRITE);
        assert_eq!(
            classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA),
            Err(GuestCowClass::NotArmed(GuestCowNotArmed::NotCowArmed))
        );
        // Nothing mapped.
        assert_eq!(
            classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA + 0x10_0000),
            Err(GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped))
        );
        // A block terminal above L3 needs a split: not EL1's.
        words.set(0x3000 + ((VA >> 21) & 511) * 8, OLD | 1 | AF);
        assert_eq!(
            classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA),
            Err(GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped))
        );
    }

    #[test]
    fn an_already_writable_leaf_is_a_retry() {
        let words = Words::new();
        words.leaf_at(VA, (armed(OLD, true) & !COW & !AP_MASK) | AP_RW);
        assert_eq!(
            classify_guest_cow_write(&words, SubstrateGpa(ROOT), VA + 8),
            Err(GuestCowClass::AlreadyWritable)
        );
    }
}
